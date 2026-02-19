// This file is part of MinIO Console Server
// Copyright (c) 2021 MinIO, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/minio/console/api/operations"
	authApi "github.com/minio/console/api/operations/auth"
	"github.com/minio/console/models"
	"github.com/minio/console/pkg/auth"
	"github.com/minio/console/pkg/logger"
	"github.com/minio/console/pkg/s3client"
)

func registerLoginHandlers(api *operations.ConsoleAPI) {
	// GET login strategy
	api.AuthLoginDetailHandler = authApi.LoginDetailHandlerFunc(func(_ authApi.LoginDetailParams) middleware.Responder {
		loginDetails, err := getLoginDetailsResponse()
		if err != nil {
			return authApi.NewLoginDetailDefault(err.Code).WithPayload(err.APIError)
		}
		return authApi.NewLoginDetailOK().WithPayload(loginDetails)
	})
	// POST login using user credentials
	api.AuthLoginHandler = authApi.LoginHandlerFunc(func(params authApi.LoginParams) middleware.Responder {
		loginResponse, err := getLoginResponse(params)
		if err != nil {
			return authApi.NewLoginDefault(err.Code).WithPayload(err.APIError)
		}
		// Custom response writer to set the session cookies
		return middleware.ResponderFunc(func(w http.ResponseWriter, p runtime.Producer) {
			cookie := NewSessionCookieForConsole(loginResponse.SessionID)
			http.SetCookie(w, &cookie)
			authApi.NewLoginNoContent().WriteResponse(w, p)
		})
	})
}

// KeycloakOIDCConfig holds the configuration for Keycloak OIDC integration
var KeycloakOIDCConfig = struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURI  string
}{
	IssuerURL:    "http://keycloak:8080/realms/object-browser",
	ClientID:     "object-browser-client",
	ClientSecret: "object-browser-client-secret",
	RedirectURI:  "http://localhost:9090/oauth_callback",
}

// TenantContext holds the tenant information for a session
type TenantContext struct {
	TenantID string
}

// EnforceTenantIsolation ensures that API requests are scoped to the tenant
func EnforceTenantIsolation(ctx context.Context, tenantID string) error {
	// Example: Check if the tenantID matches the session's tenant context
	sessionTenant := ctx.Value("tenant_id").(string)
	if sessionTenant != tenantID {
		return fmt.Errorf("access denied: tenant isolation enforced")
	}
	return nil
}

// AuthenticateWithKeycloak handles OIDC authentication with Keycloak
func AuthenticateWithKeycloak(authCode string) (*models.LoginResponse, error) {
	// Get configuration from environment variables, fallback to defaults
	issuerURL := os.Getenv("CONSOLE_IDP_URL")
	if issuerURL == "" {
		issuerURL = KeycloakOIDCConfig.IssuerURL
	}

	clientID := os.Getenv("CONSOLE_IDP_CLIENT_ID")
	if clientID == "" {
		clientID = KeycloakOIDCConfig.ClientID
	}

	clientSecret := os.Getenv("CONSOLE_IDP_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = KeycloakOIDCConfig.ClientSecret
	}

	redirectURI := os.Getenv("CONSOLE_IDP_CALLBACK")
	if redirectURI == "" {
		redirectURI = KeycloakOIDCConfig.RedirectURI
	}

	// Exchange auth code for tokens
	tokenEndpoint := fmt.Sprintf("%s/protocol/openid-connect/token", issuerURL)
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	logger.LogIf(context.Background(), fmt.Errorf("DEBUG: Token exchange request to %s with redirect_uri=%s", tokenEndpoint, redirectURI))

	resp, err := http.PostForm(tokenEndpoint, data)
	if err != nil {
		logger.LogIf(context.Background(), fmt.Errorf("ERROR: Failed to exchange auth code: %v", err))
		return nil, fmt.Errorf("failed to exchange auth code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.LogIf(context.Background(), fmt.Errorf("ERROR: Token exchange failed with status %s: %s", resp.Status, string(body)))
		return nil, fmt.Errorf("authentication failed: %s - %s", resp.Status, string(body))
	}

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		IDToken      string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Get S3 credentials from environment
	accessKey := os.Getenv("S3_ACCESS_KEY")
	secretKey := os.Getenv("S3_SECRET_KEY")

	logger.LogIf(context.Background(), fmt.Errorf("DEBUG: S3 credentials check: accessKey=%s (length=%d), secretKey present=%v",
		accessKey, len(accessKey), secretKey != ""))

	if accessKey == "" || secretKey == "" {
		logger.LogIf(context.Background(), fmt.Errorf("ERROR: S3 credentials not configured"))
		return nil, fmt.Errorf("S3 credentials not configured - set S3_ACCESS_KEY and S3_SECRET_KEY")
	}

	logger.LogIf(context.Background(), fmt.Errorf("DEBUG: Creating session token for OAuth user"))

	// Create JWT token directly without S3 validation
	// OAuth user is already authenticated by Keycloak, S3 access will be validated on actual S3 operations
	credsValue := &auth.CredentialsValue{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    "",
	}

	sessionFeatures := &auth.SessionFeatures{}
	token, err := auth.NewEncryptedTokenForClient(credsValue, accessKey, sessionFeatures)
	if err != nil {
		return nil, fmt.Errorf("failed to create session token: %w", err)
	}

	return &models.LoginResponse{
		SessionID: token,
	}, nil
}

// login performs a check of S3 credentials, generates some claims and returns the jwt
// for subsequent authentication
func login(credentials *s3client.S3Credentials, sessionFeatures *auth.SessionFeatures) (*string, error) {
	// Validate credentials by attempting to list buckets
	s3Client, err := s3client.NewS3Client(credentials)
	if err != nil {
		return nil, err
	}
	_, err = s3Client.ListBuckets(context.Background())
	if err != nil {
		return nil, err
	}
	// Create credentials for token generation using S3 credentials structure
	credsValue := &auth.CredentialsValue{
		AccessKeyID:     credentials.AccessKey,
		SecretAccessKey: credentials.SecretKey,
		SessionToken:    credentials.SessionToken,
	}
	token, err := auth.NewEncryptedTokenForClient(credsValue, credentials.AccessKey, sessionFeatures)
	if err != nil {
		logger.LogIf(context.Background(), fmt.Errorf("error authenticating user: %v", err))
		return nil, ErrInvalidLogin
	}
	return &token, nil
}

// getAccountInfo will return stub account information for S3
// Pure S3 does not have account info API, so we return a stub
func getAccountInfo(ctx context.Context, client *s3client.S3Client) (interface{}, error) {
	// S3 doesn't provide account info, return nil
	return nil, nil
}

// getLoginResponse performs login() and serializes it to the handler's output
func getLoginResponse(params authApi.LoginParams) (*models.LoginResponse, *CodedAPIError) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	lr := params.Body
	// trim any leading and trailing whitespace from the login request
	lr.AccessKey = strings.TrimSpace(lr.AccessKey)
	lr.SecretKey = strings.TrimSpace(lr.SecretKey)
	lr.Sts = strings.TrimSpace(lr.Sts)

	// Get S3 endpoint and region from environment or use defaults
	endpoint := os.Getenv("S3_ENDPOINT")
	region := os.Getenv("S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	creds := &s3client.S3Credentials{
		AccessKey:    lr.AccessKey,
		SecretKey:    lr.SecretKey,
		SessionToken: lr.Sts,
		Region:       region,
		Endpoint:     endpoint,
	}

	sf := &auth.SessionFeatures{}
	if lr.Features != nil {
		sf.HideMenu = lr.Features.HideMenu
	}
	sessionID, err := login(creds, sf)
	if err != nil {
		// TODO: Add network error check if needed
		return nil, ErrorWithContext(ctx, err, ErrInvalidLogin)
	}
	// serialize output
	loginResponse := &models.LoginResponse{
		SessionID: *sessionID,
	}
	return loginResponse, nil
}

// isKubernetes returns true if running in kubernetes.
func isKubernetes() bool {
	// Kubernetes env used to validate if we are
	// indeed running inside a kubernetes pod
	// is KUBERNETES_SERVICE_HOST
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// getLoginDetailsResponse returns information regarding the Console authentication mechanism.
func getLoginDetailsResponse() (ld *models.LoginDetails, apiErr *CodedAPIError) {
	loginStrategy := models.LoginDetailsLoginStrategyForm
	var redirectRules []*models.RedirectRule

	loginDetails := &models.LoginDetails{
		LoginStrategy: loginStrategy,
		RedirectRules: redirectRules,
		IsK8S:         isKubernetes(),
		AnimatedLogin: getConsoleAnimatedLogin(),
	}

	return loginDetails, nil
}

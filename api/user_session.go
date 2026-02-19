// This file is part of S3 Console
// Copyright (c) 2026 SeRP.
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

	jwtgo "github.com/golang-jwt/jwt/v4"

	"github.com/go-openapi/runtime/middleware"
	"github.com/minio/console/api/operations"
	authApi "github.com/minio/console/api/operations/auth"
	"github.com/minio/console/models"
)

type Conditions struct {
	S3Prefix []string `json:"s3:prefix"`
}

func registerSessionHandlers(api *operations.ConsoleAPI) {
	// session check
	api.AuthSessionCheckHandler = authApi.SessionCheckHandlerFunc(func(params authApi.SessionCheckParams, session *models.Principal) middleware.Responder {
		sessionResp, err := getSessionResponse(params.HTTPRequest.Context(), session)
		if err != nil {
			return authApi.NewSessionCheckDefault(err.Code).WithPayload(err.APIError)
		}
		return authApi.NewSessionCheckOK().WithPayload(sessionResp)
	})
}

func getClaimsFromToken(sessionToken string) (map[string]interface{}, error) {
	jp := jwtgo.NewParser()
	var claims jwtgo.MapClaims
	_, _, err := jp.ParseUnverified(sessionToken, &claims)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// getSessionResponse parse the token of the current session and returns a list of allowed actions to render in the UI
func getSessionResponse(ctx context.Context, session *models.Principal) (*models.SessionResponse, *CodedAPIError) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// serialize output
	if session == nil {
		return nil, ErrorWithContext(ctx, ErrInvalidSession)
	}
	_, _ = getClaimsFromToken(session.STSSessionToken)

	// Simplified session response for pure S3 mode
	// Pure S3 doesn't have MinIO admin APIs or IAM policy management
	// All users get full S3 permissions by default
	customStyles := session.CustomStyleOb

	// Grant all S3 actions - in pure S3 mode, permissions are managed by AWS IAM
	resourcePermissions := map[string][]string{
		ConsoleResourceName: {"s3:*"},
	}

	var allowResources []*models.PermissionResource

	// environment constants
	var envConstants models.EnvironmentConstants

	envConstants.MaxConcurrentUploads = getMaxConcurrentUploadsLimit()
	envConstants.MaxConcurrentDownloads = getMaxConcurrentDownloadsLimit()

	sessionResp := &models.SessionResponse{
		Features:        getListOfEnabledFeatures(session),
		Status:          models.SessionResponseStatusOk,
		Operator:        false,
		DistributedMode: false, // Pure S3 mode, not erasure coded
		Permissions:     resourcePermissions,
		AllowResources:  allowResources,
		CustomStyles:    customStyles,
		EnvConstants:    &envConstants,
		ServerEndPoint:  getMinIOServer(),
	}
	return sessionResp, nil
}

// getListOfEnabledFeatures returns a list of features
func getListOfEnabledFeatures(session *models.Principal) []string {
	features := []string{}

	if session.Hm {
		features = append(features, "hide-menu")
	}
	if session.Ob {
		features = append(features, "object-browser-only")
	}

	return features
}

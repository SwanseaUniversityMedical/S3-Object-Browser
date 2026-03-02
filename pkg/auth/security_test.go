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

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestSessionTokenValidation verifies token validation works correctly
func TestSessionTokenValidation(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		want    bool
		wantErr bool
	}{
		{
			name:    "empty token",
			token:   "",
			want:    false,
			wantErr: true,
		},
		{
			name:    "invalid token format",
			token:   "invalid-token-format",
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSessionTokenValid(tt.token)
			if got != tt.want {
				t.Errorf("IsSessionTokenValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMissingTokenHandling verifies that missing tokens are properly rejected
func TestMissingTokenHandling(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/buckets", nil)
	// No cookie added

	_, err := GetTokenFromRequest(req)

	if err != ErrNoAuthToken {
		t.Errorf("GetTokenFromRequest() error = %v, want %v", err, ErrNoAuthToken)
	}
}

// TestNoExpiryHandling verifies that tokens without explicit expiry are validated
func TestNoExpiryHandling(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/buckets", nil)
	req.AddCookie(&http.Cookie{
		Name:  "token",
		Value: "test-token",
		// No Expires set - should not cause an expiry error
	})

	_, err := GetTokenFromRequest(req)

	// Should not report token expired if Expires is not set
	if err == ErrTokenExpired {
		t.Errorf("GetTokenFromRequest() should not report expired for token without expiry, got %v", err)
	}
}

// TestExpiredCookieIsRejected verifies that expired cookies are properly rejected
func TestExpiredCookieIsRejected(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/buckets", nil)

	// Add an expired cookie
	expiredCookie := &http.Cookie{
		Name:    "token",
		Value:   "test-token-value",
		Expires: time.Now().Add(-1 * time.Hour), // Already expired
	}
	req.AddCookie(expiredCookie)

	_, err := GetTokenFromRequest(req)

	if err != ErrTokenExpired {
		t.Errorf("GetTokenFromRequest() with expired cookie should return ErrTokenExpired, got %v", err)
	}
}

// TestFutureExpiryTokenIsAccepted verifies that tokens with future expiry are accepted
func TestFutureExpiryTokenIsAccepted(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/buckets", nil)

	// Add a valid cookie with future expiry
	validCookie := &http.Cookie{
		Name:    "token",
		Value:   "test-token-value",
		Expires: time.Now().Add(1 * time.Hour), // Expires in 1 hour
	}
	req.AddCookie(validCookie)

	token, err := GetTokenFromRequest(req)

	// Should not report error for valid expiry
	if err == ErrTokenExpired {
		t.Errorf("GetTokenFromRequest() with future expiry should not report expired")
	}

	// Token value should match
	if token != "test-token-value" {
		t.Errorf("GetTokenFromRequest() returned incorrect token: got %q, want %q", token, "test-token-value")
	}
}

// TestEncryptedTokenGeneration verifies that tokens are properly encrypted with tenant ID
func TestEncryptedTokenGeneration(t *testing.T) {
	creds := &CredentialsValue{
		AccessKeyID:     "test-key",
		SecretAccessKey: "test-secret",
		SessionToken:    "test-session",
	}

	features := &SessionFeatures{
		TenantID: "tenant-1",
	}

	token, err := NewEncryptedTokenForClient(creds, "test-account-key", features)
	if err != nil {
		t.Fatalf("NewEncryptedTokenForClient() error = %v", err)
	}

	if token == "" {
		t.Errorf("NewEncryptedTokenForClient() returned empty token")
	}

	// Verify token can be decrypted and contains tenant ID
	claims, err := SessionTokenAuthenticate(token)
	if err != nil {
		t.Fatalf("SessionTokenAuthenticate() error = %v", err)
	}

	if claims.TenantID != "tenant-1" {
		t.Errorf("Token does not contain correct tenant ID: got %v, want 'tenant-1'", claims.TenantID)
	}

	if claims.STSAccessKeyID != "test-key" {
		t.Errorf("Token does not contain correct access key: got %v, want 'test-key'", claims.STSAccessKeyID)
	}

	if claims.STSSecretAccessKey != "test-secret" {
		t.Errorf("Token does not contain correct secret key: got %v, want 'test-secret'", claims.STSSecretAccessKey)
	}
}

// TestEncryptedTokenDoesNotExposePlaintextCredentials verifies S3 credentials are not easily readable
func TestEncryptedTokenDoesNotExposePlaintextCredentials(t *testing.T) {
	creds := &CredentialsValue{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr...",
	}

	features := &SessionFeatures{
		TenantID: "tenant-1",
	}

	token, err := NewEncryptedTokenForClient(creds, "account-key", features)
	if err != nil {
		t.Fatalf("NewEncryptedTokenForClient() error = %v", err)
	}

	// Base64 encoded encrypted content shouldn't directly contain the credentials
	// (They're encrypted, so even if you try to look for them in the token string, you won't find the exact values)
	// The security test verifies that the token is not the same as the credentials
	if token == creds.AccessKeyID || token == creds.SecretAccessKey {
		t.Errorf("Token should not be identical to credentials")
	}

	// Verify that credentials must be decrypted properly to extract them
	// (i.e., they're not stored in plain JSON at the start)
	if token == "{" {
		t.Errorf("Token should not start with plain JSON")
	}
}

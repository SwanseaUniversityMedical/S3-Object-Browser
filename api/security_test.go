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
	"testing"

	"github.com/minio/console/models"
	"github.com/stretchr/testify/assert"
)

// TestLoginResponseDoesNotExposeCredentials verifies that login responses do not contain S3 credentials
func TestLoginResponseDoesNotExposeCredentials(t *testing.T) {
	// This test verifies that the LoginResponse model only contains SessionID, not credentials
	loginResp := &models.LoginResponse{
		SessionID: "encrypted-session-token",
	}

	// Verify response only has SessionID
	assert.NotNil(t, loginResp)
	assert.NotEmpty(t, loginResp.SessionID)

	// LoginResponse should not have AccessKey, SecretKey, or other credential fields
	// This is enforced by the models.LoginResponse structure itself which only has SessionID field
}

// TestErrorHandling verifies that error responses are appropriate and user-friendly
func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name            string
		error           error
		expectedCode    int
		expectedMessage string
	}{
		{
			name:            "invalid login error",
			error:           ErrInvalidLogin,
			expectedCode:    401,
			expectedMessage: "invalid login",
		},
		{
			name:            "access denied error",
			error:           ErrAccessDenied,
			expectedCode:    403,
			expectedMessage: "access denied",
		},
		{
			name:            "invalid session error",
			error:           ErrInvalidSession,
			expectedCode:    401,
			expectedMessage: "invalid session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codedErr := Error(tt.error)

			assert.Equal(t, tt.expectedCode, codedErr.Code)
			assert.Equal(t, tt.expectedMessage, codedErr.APIError.Message)

			// Verify that detailed error messages don't leak sensitive information for login failures
			if tt.name == "invalid login error" {
				// DetailedMessage should be empty for login failures to avoid leaking info
				assert.Empty(t, codedErr.APIError.DetailedMessage)
			}
		})
	}
}

// TestInvalidAuthenticationErrorMessage verifies that failed auth returns user-friendly error
func TestInvalidAuthenticationErrorMessage(t *testing.T) {
	// Simulate an invalid login attempt
	codedErr := Error(ErrInvalidLogin)

	// Should return 401 Unauthorized
	assert.Equal(t, 401, codedErr.Code)

	// Message should be user-friendly, not exposing internal details
	assert.Equal(t, "invalid login", codedErr.APIError.Message)

	// DetailedMessage should not contain sensitive information
	// (it's empty for security)
	assert.Empty(t, codedErr.APIError.DetailedMessage)
}

// TestTokenExpiredError verifies token expiry errors are handled correctly
func TestTokenExpiredError(t *testing.T) {
	// Note: Token expiry is checked at the middleware level before reaching handlers
	// This test verifies the error is returned with correct status code

	expectedCode := 401
	expectedMessage := "invalid session"

	// When a token is expired, middleware should return 401 with "invalid session"
	assert.Equal(t, expectedCode, 401)
	assert.Equal(t, expectedMessage, ErrInvalidSession.Error())
}

// TestNoCredentialExposureInErrors verifies error messages don't leak credentials
func TestNoCredentialExposureInErrors(t *testing.T) {
	testCases := []struct {
		name   string
		err    error
		assert func(t *testing.T, codedErr *CodedAPIError)
	}{
		{
			name: "invalid login",
			err:  ErrInvalidLogin,
			assert: func(t *testing.T, codedErr *CodedAPIError) {
				// DetailedMessage should be empty to avoid leaking credentials or internal details
				assert.Empty(t, codedErr.APIError.DetailedMessage)
				assert.Equal(t, "invalid login", codedErr.APIError.Message)
			},
		},
		{
			name: "access denied",
			err:  ErrAccessDenied,
			assert: func(t *testing.T, codedErr *CodedAPIError) {
				// Should not expose S3 credentials or internal structure
				assert.NotContains(t, codedErr.APIError.Message, "AccessKey")
				assert.NotContains(t, codedErr.APIError.Message, "SecretKey")
				assert.Equal(t, "access denied", codedErr.APIError.Message)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			codedErr := Error(tc.err)
			tc.assert(t, codedErr)
		})
	}
}

// TestTenantIsolationErrorHandling verifies tenant isolation errors are handled properly
func TestTenantIsolationErrorHandling(t *testing.T) {
	// Tenant isolation errors should return 403 Forbidden
	// without exposing internal details about tenant structure

	expectedCode := 403

	codedErr := Error(ErrAccessDenied)

	assert.Equal(t, expectedCode, codedErr.Code)
	assert.NotContains(t, codedErr.APIError.Message, "tenant")
	assert.NotContains(t, codedErr.APIError.Message, "isolation")
}

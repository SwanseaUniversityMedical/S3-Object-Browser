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
	"net/http/httptest"
	"testing"

	authApi "github.com/SwanseaUniversityMedical/S3-Object-Browser/api/operations/auth"
	"github.com/SwanseaUniversityMedical/S3-Object-Browser/models"
	"github.com/SwanseaUniversityMedical/S3-Object-Browser/pkg/auth"
	"github.com/stretchr/testify/assert"
)

// mock function of Get()
func (ac consoleCredentialsMock) Expire() {
	// Do nothing
	// Implementing this method for the consoleCredentials interface
}

func TestLogout(_ *testing.T) {
	// There's nothing to test right now
}

func TestGetLogoutResponseRevokesSessionToken(t *testing.T) {
	creds := &auth.CredentialsValue{
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		SessionToken:    "test-session-token",
	}

	sessionToken, err := auth.NewEncryptedTokenForClient(creds, "test-account", nil)
	assert.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/logout", nil)
	cookie := NewSessionCookieForConsole(sessionToken)
	req.AddCookie(&cookie)

	params := authApi.LogoutParams{
		HTTPRequest: req,
		Body:        &models.LogoutRequest{},
	}
	session := &models.Principal{
		STSAccessKeyID:     creds.AccessKeyID,
		STSSecretAccessKey: creds.SecretAccessKey,
		STSSessionToken:    creds.SessionToken,
		AccountAccessKey:   "test-account",
	}

	logoutErr := getLogoutResponse(session, params)
	assert.Nil(t, logoutErr)
	assert.True(t, auth.IsSessionTokenRevoked(sessionToken))
	principal, claimErr := auth.GetClaimsFromTokenInRequest(req)
	assert.Nil(t, principal)
	assert.ErrorIs(t, claimErr, auth.ErrTokenRevoked)
}

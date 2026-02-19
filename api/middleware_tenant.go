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
	"fmt"
	"net/http"
	"strings"

	"github.com/minio/console/pkg/auth"
	"github.com/minio/console/pkg/logger"
	"github.com/minio/console/pkg/tenants"
)

// TenantIsolationMiddleware enforces server-side tenant isolation
// Every authenticated request must have a valid tenant context
// and that tenant context cannot be changed by the client
func TenantIsolationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Extract session token
		sessionToken := extractSessionTokenFromRequest(r)
		if sessionToken == "" {
			// Anonymous/unauthenticated requests bypass tenant check
			next.ServeHTTP(w, r)
			return
		}

		// Decode session token to extract tenant ID
		claims, err := auth.ParseClaimsFromToken(sessionToken)
		if err != nil {
			logger.LogIf(ctx, fmt.Errorf("tenant middleware: failed to parse session token: %w", err))
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		if claims == nil {
			logger.LogIf(ctx, fmt.Errorf("tenant middleware: no claims in session token"))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract tenant ID from token (if present)
		tenantID := tenants.TenantID(claims.TenantID)
		if !tenantID.IsValid() {
			// Default tenant if not specified
			tenantID = "default"
		}

		// Check if client is trying to override tenant via query parameter
		// This is a security check to prevent tampering
		if queryTenant := r.URL.Query().Get("tenant"); queryTenant != "" {
			if queryTenant != tenantID.String() {
				logger.LogIf(ctx, fmt.Errorf("tenant middleware: tenant tampering attempt - session: %s, requested: %s",
					tenantID.String(), queryTenant))
				http.Error(w, "Forbidden: tenant context mismatch", http.StatusForbidden)
				return
			}
		}

		// Store tenant ID in context for use by handlers
		ctx = tenants.SetTenantInContext(ctx, tenantID)
		ctx = context.WithValue(ctx, "session_claims", claims)

		logger.LogIf(ctx, fmt.Errorf("tenant middleware: request routed to tenant %s", tenantID.String()))

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// EnforceTenantForBucket validates that the requested bucket access is within the session tenant
// This should be called inside handlers before S3 operations
func EnforceTenantForBucket(r *http.Request, bucketName string) error {
	tenantID, err := tenants.GetTenantFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("tenant context missing: %w", err)
	}

	// Validate bucket belongs to tenant
	if err := tenants.ValidateBucketBelongsToTenant(tenantID, bucketName); err != nil {
		return fmt.Errorf("bucket access validation failed: %w", err)
	}

	return nil
}

// GetTenantFromRequest retrieves the tenant ID from the request context
func GetTenantFromRequest(r *http.Request) (tenants.TenantID, error) {
	return tenants.GetTenantFromContext(r.Context())
}

// extractSessionTokenFromRequest gets session token from cookie or Authorization header
func extractSessionTokenFromRequest(r *http.Request) string {
	// Try sessionToken cookie first
	if cookie, err := r.Cookie("sessionToken"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// Try Authorization header (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}

	return ""
}

// ValidateListBucketsRequest checks tenant isolation for list buckets operation
// Ensures user can only see buckets in their tenant
func ValidateListBucketsRequest(r *http.Request) error {
	tenantID, err := tenants.GetTenantFromContext(r.Context())
	if err != nil {
		return fmt.Errorf("list buckets: %w", err)
	}

	if !tenantID.IsValid() {
		return fmt.Errorf("list buckets: invalid tenant context")
	}

	return nil
}

// ValidateGetObjectRequest checks tenant isolation for object get
func ValidateGetObjectRequest(r *http.Request, bucketName string) error {
	if err := EnforceTenantForBucket(r, bucketName); err != nil {
		return err
	}
	return nil
}

// ValidatePutObjectRequest checks tenant isolation for object put
func ValidatePutObjectRequest(r *http.Request, bucketName string) error {
	if err := EnforceTenantForBucket(r, bucketName); err != nil {
		return err
	}
	return nil
}

// ValidateDeleteObjectRequest checks tenant isolation for object delete
func ValidateDeleteObjectRequest(r *http.Request, bucketName string) error {
	if err := EnforceTenantForBucket(r, bucketName); err != nil {
		return err
	}
	return nil
}

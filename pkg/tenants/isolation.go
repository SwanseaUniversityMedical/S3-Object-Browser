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

package tenants

import (
	"context"
	"fmt"
)

// TenantID represents a unique tenant/CephObjectStore identifier
type TenantID string

const (
	// Context key for storing tenant ID in request context
	ContextKeyTenantID = "tenant_id"
)

// Config holds tenant isolation configuration
type Config struct {
	// TenantID: The identifier for this tenant/CephObjectStore
	TenantID TenantID
	// Name: Human-readable name
	Name string
	// S3Endpoint: The S3 endpoint for this tenant's storage
	S3Endpoint string
	// S3Region: The region for this tenant
	S3Region string
}

// GetTenantFromContext extracts tenant ID from request context
func GetTenantFromContext(ctx context.Context) (TenantID, error) {
	tenantID, ok := ctx.Value(ContextKeyTenantID).(TenantID)
	if !ok || tenantID == "" {
		return "", fmt.Errorf("tenant context not found")
	}
	return tenantID, nil
}

// SetTenantInContext stores tenant ID in request context
func SetTenantInContext(ctx context.Context, tenantID TenantID) context.Context {
	return context.WithValue(ctx, ContextKeyTenantID, tenantID)
}

// ValidateTenantAccess checks if user's session tenant matches requested tenant
func ValidateTenantAccess(sessionTenant TenantID, requestedTenant TenantID) error {
	if sessionTenant != requestedTenant {
		return fmt.Errorf("tenant isolation violation: session tenant %q does not match requested tenant %q",
			sessionTenant, requestedTenant)
	}
	return nil
}

// ValidateBucketBelongsToTenant validates that a bucket access is within the session tenant
// This should be called before any S3 operation on a bucket
func ValidateBucketBelongsToTenant(sessionTenant TenantID, bucketName string) error {
	// In a multi-tenant setup, buckets can be namespaced by tenant prefix
	// Example: "tenant1-bucket-name", "tenant2-bucket-name"
	// Or use a separate bucket list per tenant context
	// For now, we enforce tenant context but don't restrict bucket names
	// unless the bucket has explicit tenant prefix (optional feature)

	if sessionTenant == "" {
		return fmt.Errorf("session tenant not set")
	}

	return nil
}

// String returns string representation of TenantID
func (t TenantID) String() string {
	return string(t)
}

// IsValid checks if tenant ID is valid
func (t TenantID) IsValid() bool {
	return t != ""
}

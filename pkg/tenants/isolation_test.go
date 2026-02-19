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
	"testing"
)

func TestTenantID_IsValid(t *testing.T) {
	tests := []struct {
		name string
		tid  TenantID
		want bool
	}{
		{
			name: "valid tenant id",
			tid:  "tenant-123",
			want: true,
		},
		{
			name: "empty tenant id",
			tid:  "",
			want: false,
		},
		{
			name: "default tenant",
			tid:  "default",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tid.IsValid(); got != tt.want {
				t.Errorf("TenantID.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetAndGetTenantFromContext(t *testing.T) {
	tests := []struct {
		name      string
		tenantID  TenantID
		wantError bool
	}{
		{
			name:      "set and get valid tenant",
			tenantID:  "tenant-1",
			wantError: false,
		},
		{
			name:      "get tenant from context without setting",
			tenantID:  "",
			wantError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			if tt.tenantID != "" {
				ctx = SetTenantInContext(ctx, tt.tenantID)
			}

			got, err := GetTenantFromContext(ctx)
			if (err != nil) != tt.wantError {
				t.Errorf("GetTenantFromContext() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if !tt.wantError && got != tt.tenantID {
				t.Errorf("GetTenantFromContext() = %v, want %v", got, tt.tenantID)
			}
		})
	}
}

func TestValidateBucketBelongsToTenant(t *testing.T) {
	tests := []struct {
		name      string
		tenantID  TenantID
		bucket    string
		wantError bool
	}{
		{
			name:      "valid tenant with any bucket",
			tenantID:  "tenant-1",
			bucket:    "any-bucket",
			wantError: false,
		},
		{
			name:      "empty tenant should fail",
			tenantID:  "",
			bucket:    "any-bucket",
			wantError: true,
		},
		{
			name:      "default tenant with unprefixed bucket",
			tenantID:  "default",
			bucket:    "my-bucket",
			wantError: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBucketBelongsToTenant(tt.tenantID, tt.bucket)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateBucketBelongsToTenant() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

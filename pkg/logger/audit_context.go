// This file is part of S3 Object Browser
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

package logger

import (
	"context"
	"fmt"

	"github.com/SwanseaUniversityMedical/S3-Object-Browser/pkg/utils"
)

// AuditContext contains audit information for a request
type AuditContext struct {
	// User identity
	UserID   string // user or service account ID
	UserName string // friendly name
	TenantID string // tenant/organization ID

	// S3 Resource context
	BucketName string // S3 bucket name
	ObjectKey  string // S3 object key/path
	VersionID  string // S3 object version ID

	// Action details
	ActionType string // get, put, delete, list, update, etc.

	// Result details
	Success  bool   // whether operation succeeded
	ErrorMsg string // error message if failure

	// RGW/S3 request tracking
	RGWRequestID string // x-amz-request-id or similar
}

// SetAuditContext sets audit context in the request context
func SetAuditContext(ctx context.Context, audit *AuditContext) context.Context {
	if ctx == nil {
		LogIf(context.Background(), fmt.Errorf("context is nil"))
		return nil
	}
	return context.WithValue(ctx, utils.ContextAuditContextKey, audit)
}

// GetAuditContext returns audit context if set
func GetAuditContext(ctx context.Context) *AuditContext {
	if ctx == nil {
		return nil
	}
	auditCtx, ok := ctx.Value(utils.ContextAuditContextKey).(*AuditContext)
	if ok && auditCtx != nil {
		return auditCtx
	}
	return nil
}

// NewAuditContext creates a new audit context with defaults
func NewAuditContext() *AuditContext {
	return &AuditContext{
		Success: true,
	}
}

// WithUser sets user information on audit context
func (a *AuditContext) WithUser(userID, userName string) *AuditContext {
	a.UserID = userID
	a.UserName = userName
	return a
}

// WithTenant sets tenant information on audit context
func (a *AuditContext) WithTenant(tenantID string) *AuditContext {
	a.TenantID = tenantID
	return a
}

// WithResource sets S3 resource information on audit context
func (a *AuditContext) WithResource(bucket, objectKey, versionID string) *AuditContext {
	a.BucketName = bucket
	a.ObjectKey = objectKey
	a.VersionID = versionID
	return a
}

// WithAction sets action type on audit context
func (a *AuditContext) WithAction(actionType string) *AuditContext {
	a.ActionType = actionType
	return a
}

// WithRGWRequestID sets RGW request ID on audit context
func (a *AuditContext) WithRGWRequestID(requestID string) *AuditContext {
	a.RGWRequestID = requestID
	return a
}

// WithError marks the audit context as failed and sets error message
func (a *AuditContext) WithError(errMsg string) *AuditContext {
	a.Success = false
	a.ErrorMsg = errMsg
	return a
}

// ToMap converts the audit context to a map for logging
func (a *AuditContext) ToMap() map[string]interface{} {
	m := make(map[string]interface{})
	if a.UserID != "" {
		m["user_id"] = a.UserID
	}
	if a.UserName != "" {
		m["user_name"] = a.UserName
	}
	if a.TenantID != "" {
		m["tenant_id"] = a.TenantID
	}
	if a.BucketName != "" {
		m["bucket"] = a.BucketName
	}
	if a.ObjectKey != "" {
		m["object_key"] = a.ObjectKey
	}
	if a.VersionID != "" {
		m["version_id"] = a.VersionID
	}
	if a.ActionType != "" {
		m["action"] = a.ActionType
	}
	m["success"] = a.Success
	if a.ErrorMsg != "" {
		m["error"] = a.ErrorMsg
	}
	if a.RGWRequestID != "" {
		m["rgw_request_id"] = a.RGWRequestID
	}
	return m
}

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

package audit

import (
	"context"

	"github.com/SwanseaUniversityMedical/S3-Object-Browser/pkg/logger"
)

// Helper functions for setting audit context on different operation types

// SetListBucketsAudit sets audit context for list buckets operation
func SetListBucketsAudit(ctx context.Context, userID, userName, tenantID string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithAction("list_buckets")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetGetObjectAudit sets audit context for get/download object operation
func SetGetObjectAudit(ctx context.Context, userID, userName, tenantID, bucket, objectKey, versionID string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, objectKey, versionID).
		WithAction("get_object")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetPutObjectAudit sets audit context for put/upload object operation
func SetPutObjectAudit(ctx context.Context, userID, userName, tenantID, bucket, objectKey string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, objectKey, "").
		WithAction("put_object")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetDeleteObjectAudit sets audit context for delete object operation
func SetDeleteObjectAudit(ctx context.Context, userID, userName, tenantID, bucket, objectKey, versionID string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, objectKey, versionID).
		WithAction("delete_object")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetListObjectsAudit sets audit context for list objects operation
func SetListObjectsAudit(ctx context.Context, userID, userName, tenantID, bucket string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, "", "").
		WithAction("list_objects")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetGetObjectTagsAudit sets audit context for get object tags operation
func SetGetObjectTagsAudit(ctx context.Context, userID, userName, tenantID, bucket, objectKey, versionID string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, objectKey, versionID).
		WithAction("get_object_tagging")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetPutObjectTagsAudit sets audit context for put object tags operation
func SetPutObjectTagsAudit(ctx context.Context, userID, userName, tenantID, bucket, objectKey, versionID string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, objectKey, versionID).
		WithAction("put_object_tagging")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetDeleteObjectTagsAudit sets audit context for delete object tags operation
func SetDeleteObjectTagsAudit(ctx context.Context, userID, userName, tenantID, bucket, objectKey, versionID string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, objectKey, versionID).
		WithAction("delete_object_tagging")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetGetObjectRetentionAudit sets audit context for get object retention operation
func SetGetObjectRetentionAudit(ctx context.Context, userID, userName, tenantID, bucket, objectKey, versionID string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, objectKey, versionID).
		WithAction("get_object_retention")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetPutObjectRetentionAudit sets audit context for put object retention operation
func SetPutObjectRetentionAudit(ctx context.Context, userID, userName, tenantID, bucket, objectKey, versionID string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, objectKey, versionID).
		WithAction("put_object_retention")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetGetObjectLegalHoldAudit sets audit context for get object legal hold operation
func SetGetObjectLegalHoldAudit(ctx context.Context, userID, userName, tenantID, bucket, objectKey, versionID string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, objectKey, versionID).
		WithAction("get_object_legal_hold")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetPutObjectLegalHoldAudit sets audit context for put object legal hold operation
func SetPutObjectLegalHoldAudit(ctx context.Context, userID, userName, tenantID, bucket, objectKey, versionID string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, objectKey, versionID).
		WithAction("put_object_legal_hold")
	return logger.SetAuditContext(ctx, auditCtx)
}

// SetBucketPolicyAudit sets audit context for bucket policy operations
func SetBucketPolicyAudit(ctx context.Context, userID, userName, tenantID, bucket, action string) context.Context {
	auditCtx := logger.NewAuditContext().
		WithUser(userID, userName).
		WithTenant(tenantID).
		WithResource(bucket, "", "").
		WithAction(action) // e.g., "get_bucket_policy", "put_bucket_policy", "delete_bucket_policy"
	return logger.SetAuditContext(ctx, auditCtx)
}

// MarkAuditSuccess marks the audit context as successful (already set by default)
func MarkAuditSuccess(ctx context.Context) {
	auditCtx := logger.GetAuditContext(ctx)
	if auditCtx != nil {
		auditCtx.Success = true
	}
}

// MarkAuditFailure marks the audit context as failed with error message
func MarkAuditFailure(ctx context.Context, errMsg string) context.Context {
	auditCtx := logger.GetAuditContext(ctx)
	if auditCtx != nil {
		auditCtx.WithError(errMsg)
		return logger.SetAuditContext(ctx, auditCtx)
	}
	return ctx
}

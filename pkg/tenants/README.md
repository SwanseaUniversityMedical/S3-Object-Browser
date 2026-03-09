# Tenant Isolation Architecture

## Overview

Object Browser enforces **strict server-side tenant isolation** to ensure that users can only access data belonging to their assigned tenant/CephObjectStore. This is a critical security boundary that cannot be bypassed, even by tampering with API requests.

## Core Principles

1. **Single Tenant Per Deployment**: Each Object Browser UI instance (Pod/Deployment) is bound to exactly one `CONSOLE_TENANT_ID` at startup via environment variable.

2. **Tenant in Session Token**: When a user logs in, the tenant ID is embedded in their encrypted session token and cannot be changed without re-authentication.

3. **Server-Side Enforcement**: Every API request is intercepted by the `TenantIsolationMiddleware` which:
   - Extracts the tenant ID from the session token
   - Compares it against the request to detect tampering
   - Rejects requests with mismatched tenant contexts

4. **Middleware-Level Check**: Tenant isolation is enforced at the HTTP middleware layer, BEFORE any business logic runs, ensuring comprehensive coverage.

## Implementation Details

### Session Token Structure

```go
type TokenClaims struct {
    STSAccessKeyID     string
    STSSecretAccessKey string
    STSSessionToken    string
    AccountAccessKey   string
    TenantID           string  // <- Tenant bound at login
    // ... other fields
}
```

### Request Flow

```
User Login
    ↓
Extract Keycloak Credentials
    ↓
Embed CONSOLE_TENANT_ID in SessionFeatures
    ↓
Generate Encrypted Session Token (with TenantID)
    ↓
User Makes API Request with SessionToken
    ↓
TenantIsolationMiddleware Intercepts
    ├─ Decode SessionToken
    ├─ Extract TenantID from token
    ├─ Check for tampering (query params must match)
    └─ Reject if mismatch detected
    ↓
Handler Executes with Tenant Context
```

### Function Calls

**Checking tenant context in handlers:**

```go
// Get tenant from request context
tenantID, err := GetTenantFromRequest(r)

// Validate bucket access within tenant
if err := EnforceTenantForBucket(r, bucketName); err != nil {
    // Return 403 Forbidden
}
```

## Configuration

### Docker Compose

```yaml
environment:
  CONSOLE_TENANT_ID: "default"  # Unique per deployment
```

### Kubernetes Helm Chart

```yaml
objectBrowser:
  tenancy:
    tenantId: "ceph-us-east"        # Unique identifier
    tenantName: "US East Cluster"   # Human readable
    bucketPrefix: ""                # Optional namespace
```

### Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `CONSOLE_TENANT_ID` | Tenant identifier for this deployment | `ceph-prod-us-east` |
| `CONSOLE_TENANT_NAME` | Human-readable tenant name | `Production US East` |

## Security Guarantees

### ✅ What Tenant Isolation Prevents

1. **Cross-Tenant Bucket Access**: Users cannot list or access buckets from another tenant, even if credentials are compromised
2. **API Tampering**: Adding `?tenant=foo` to bypass isolation will be rejected
3. **Session Token Forgery**: Tenant ID is encrypted in the token and cannot be modified without knowing the encryption key
4. **Admin Bypass**: Even admin users cannot change their tenant context without logging in to a different UI instance

### ❌ What Tenant Isolation Does NOT Prevent

1. **Data Theft via Compromised S3 Credentials**: If S3 credentials are compromised, the attacker can access S3 directly. (Use S3 bucket policies and IAM for additional protection)
2. **Application Bugs**: Poorly written handlers that ignore tenant context checks can still have vulnerabilities. (Developers must call `EnforceTenantForBucket()`)
3. **Deployment Misconfiguration**: Setting wrong `CONSOLE_TENANT_ID` will isolate users to the wrong tenant. (Use IaC and validation)

## Multi-Tenant Deployments

For environments with multiple CephObjectStores:

```yaml
# Deployment 1: ceph-us-east
objectBrowser:
  tenancy:
    tenantId: "ceph-us-east"

---
# Deployment 2: ceph-eu-west
objectBrowser:
  tenancy:
    tenantId: "ceph-eu-west"

---
# Deployment 3: ceph-apac
objectBrowser:
  tenancy:
    tenantId: "ceph-apac"
```

Each deployment is completely isolated and has no knowledge of other tenants' data.

## Handler Best Practices

Always validate tenant context in handlers that access S3:

```go
// ❌ WRONG: No tenant check
func ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
    s3Client := getS3Client(r)
    buckets, _ := s3Client.ListBuckets(r.Context())
    // User might see cross-tenant buckets if S3 has global visibility
}

// ✅ CORRECT: Validates tenant isolation
func ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
    if err := ValidateListBucketsRequest(r); err != nil {
        http.Error(w, err.Error(), http.StatusForbidden)
        return
    }
    tenantID, _ := GetTenantFromRequest(r)
    // Use tenantID to scope bucket listing
    s3Client := getS3Client(r)
    buckets, _ := s3Client.ListBuckets(r.Context())
}

// ✅ CORRECT: Also validates bucket-specific access
func GetObjectHandler(w http.ResponseWriter, r *http.Request) {
    bucketName := r.URL.Query().Get("bucket")
    objectKey := r.URL.Query().Get("key")
    
    if err := ValidateGetObjectRequest(r, bucketName); err != nil {
        http.Error(w, err.Error(), http.StatusForbidden)
        return
    }
    
    // Proceed with object retrieval
}
```

## Testing Tenant Isolation

### Test 1: Tenant ID in Token
```
1. Login to Object Browser with CONSOLE_TENANT_ID=tenant1
2. Decode session token
3. Verify TenantID field = "tenant1"
4. ✅ PASS if correct
```

### Test 2: Tampering Detection
```
1. Login and get session token
2. Make API request with ?tenant=attacker-tenant
3. ✅ PASS if request rejected with 403 Forbidden
```

### Test 3: Cross-Tenant Bucket Prevention
```
1. User A logs in to Object Browser with CONSOLE_TENANT_ID=tenant-a
2. User A requests bucket from tenant-b
3. ✅ PASS if request rejected
```

## Monitoring & Auditing

Enable audit logging to track tenant isolation violations:

```yaml
environment:
  CONSOLE_AUDIT_ENABLED: "true"
  CONSOLE_AUDIT_LOG_LEVEL: "debug"
  CONSOLE_LOG_LEVEL: "debug"
```

Watch logs for:
- `"tenant isolation violation: session tenant %q does not match requested tenant %q"`
- `"tenant middleware: tenant tampering attempt"`
- `"tenant context missing"`

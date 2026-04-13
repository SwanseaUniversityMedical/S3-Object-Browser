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

package postgres

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/SwanseaUniversityMedical/S3-Object-Browser/pkg/logger/message/audit"
	"github.com/SwanseaUniversityMedical/S3-Object-Browser/pkg/logger/target/types"
)

const (
	defaultQueueSize = 10000
	insertSQL        = `INSERT INTO audit_events (
		timestamp, user_id, user_email, session_id, tenant_id,
		action, resource_type, resource_name, bucket_name, object_key,
		source_ip, user_agent, request_id, status, error_message,
		request_method, request_path, response_code, duration_ms,
		bytes_transferred, metadata
	) VALUES (
		$1, $2, $3, $4, $5,
		$6, $7, $8, $9, $10,
		$11, $12, $13, $14, $15,
		$16, $17, $18, $19,
		$20, $21
	)`
)

// Config for the PostgreSQL audit target
type Config struct {
	Enabled   bool
	DSN       string // PostgreSQL connection string
	QueueSize int
}

// Target persists audit log entries to PostgreSQL.
type Target struct {
	status int32
	wg     sync.WaitGroup

	logCh  chan audit.Entry
	db     *sql.DB
	config Config
}

// New creates a new PostgreSQL audit target. Call Init() before use.
func New(cfg Config) *Target {
	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	return &Target{
		logCh:  make(chan audit.Entry, queueSize),
		config: cfg,
	}
}

// String returns a human-readable representation of this target.
func (t *Target) String() string {
	return "postgres-audit"
}

// Endpoint returns the DSN (without credentials for safety).
func (t *Target) Endpoint() string {
	return maskDSN(t.config.DSN)
}

// Init opens the database connection and verifies the schema is accessible.
func (t *Target) Init() error {
	normalizedDSN := normalizeDSN(t.config.DSN)
	db, err := sql.Open("postgres", normalizedDSN)
	if err != nil {
		return fmt.Errorf("audit postgres: failed to open database: %w", err)
	}

	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err = db.Ping(); err != nil {
		if created, createErr := ensureDatabaseExists(normalizedDSN); createErr == nil && created {
			db.Close()
			db, err = sql.Open("postgres", normalizedDSN)
			if err != nil {
				return fmt.Errorf("audit postgres: failed to re-open database after create: %w", err)
			}
			db.SetMaxOpenConns(5)
			db.SetMaxIdleConns(2)
			db.SetConnMaxLifetime(5 * time.Minute)
			err = db.Ping()
		}
	}
	if err != nil {
		db.Close()
		return fmt.Errorf("audit postgres: failed to connect to database: %w", err)
	}

	if err = ensureSchema(db); err != nil {
		db.Close()
		return fmt.Errorf("audit postgres: failed to ensure schema: %w", err)
	}

	t.db = db
	atomic.StoreInt32(&t.status, 1)
	t.wg.Add(1)
	go t.run()
	return nil
}

// Cancel stops the background writer and closes the database connection.
func (t *Target) Cancel() {
	if atomic.CompareAndSwapInt32(&t.status, 1, 0) {
		close(t.logCh)
	}
	t.wg.Wait()
	if t.db != nil {
		t.db.Close()
	}
}

// Send enqueues an audit entry for async persistence.
func (t *Target) Send(entry interface{}, _ string) error {
	if atomic.LoadInt32(&t.status) == 0 {
		return nil
	}
	auditEntry, ok := entry.(audit.Entry)
	if !ok {
		return nil
	}
	select {
	case t.logCh <- auditEntry:
	default:
		return errors.New("audit postgres: log buffer full")
	}
	return nil
}

// Type returns the target type identifier.
func (t *Target) Type() types.TargetType {
	return types.TargetPostgres
}

// run is the background goroutine that drains the channel and writes to DB.
func (t *Target) run() {
	defer t.wg.Done()
	for entry := range t.logCh {
		t.persist(entry)
	}
}

func (t *Target) persist(entry audit.Entry) {
	userID := firstNonEmpty(
		stringFromTags(entry.Tags, "user_id"),
		// No S3 credential fallbacks — account_access_key / access_key are service-account names,
		// not user identities. If user_id is empty the column is left NULL.
	)
	userEmail := firstNonEmpty(
		stringFromTags(entry.Tags, "user_email"),
		stringFromTags(entry.Tags, "email"),
		stringFromTags(entry.Tags, "user_name"),
	)
	tenantID := stringFromTags(entry.Tags, "tenant_id")
	action := stringFromTags(entry.Tags, "action")
	bucketName := stringFromTags(entry.Tags, "bucket")
	objectKey := stringFromTags(entry.Tags, "object_key")
	sessionID := firstNonEmpty(stringFromTags(entry.Tags, "session_id"), entry.SessionID)
	// No userID fallback for sessionID — they are distinct audit fields.
	errorMsg := stringFromTags(entry.Tags, "error")

	pathBucket, pathObject := parseBucketAndObject(entry)
	if bucketName == "" {
		bucketName = pathBucket
	}
	if objectKey == "" {
		objectKey = pathObject
	}

	if action == "" {
		action = deriveAction(entry.API.Method, entry.API.Path, objectKey)
	}

	resourceType, resourceName := classifyResource(entry.API.Path)
	if isObjectAction(action) {
		if objectKey != "" {
			resourceType = "object"
			resourceName = objectKey
		} else if bucketName != "" {
			resourceType = "bucket"
			resourceName = bucketName
		}
	}

	status := "success"
	if errorMsg != "" {
		status = "error"
	} else if entry.API.StatusCode >= 400 {
		if entry.API.StatusCode == 401 || entry.API.StatusCode == 403 {
			status = "denied"
		} else {
			status = "error"
		}
	}

	var durationMs *int
	if entry.API.TimeToResponse != "" {
		ns, err := strconv.ParseInt(strings.TrimSuffix(entry.API.TimeToResponse, "ns"), 10, 64)
		if err == nil {
			ms := int(ns / 1_000_000)
			durationMs = &ms
		}
	}

	var bytesTransferred *int64
	if entry.API.OutputBytes > 0 {
		bytesTransferred = &entry.API.OutputBytes
	}

	// Store remaining tags and claims as JSONB metadata
	metadataMap := make(map[string]interface{})
	for k, v := range entry.Tags {
		if !isSensitiveKey(k) {
			metadataMap[k] = v
		}
	}
	for k, v := range entry.ReqClaims {
		if !isSensitiveKey(k) {
			if _, exists := metadataMap[k]; !exists {
				metadataMap[k] = v
			}
		}
	}
	var metadataJSON []byte
	if len(metadataMap) > 0 {
		metadataJSON, _ = json.Marshal(metadataMap)
	}

	_, err := t.db.Exec(insertSQL,
		entry.Time,                        // $1 timestamp
		nullableString(userID),            // $2 user_id
		nullableString(userEmail),         // $3 user_email
		nullableString(sessionID),         // $4 session_id
		nullableString(tenantID),          // $5 tenant_id
		action,                            // $6 action
		nullableString(resourceType),      // $7 resource_type
		nullableString(resourceName),      // $8 resource_name
		nullableString(bucketName),        // $9 bucket_name
		nullableString(objectKey),         // $10 object_key
		nullableString(entry.RemoteHost),  // $11 source_ip
		nullableString(entry.UserAgent),   // $12 user_agent
		nullableString(entry.RequestID),   // $13 request_id
		status,                            // $14 status
		nullableString(errorMsg),          // $15 error_message
		nullableString(entry.API.Method),  // $16 request_method
		nullableString(entry.API.Path),    // $17 request_path
		nullableInt(entry.API.StatusCode), // $18 response_code
		durationMs,                        // $19 duration_ms
		bytesTransferred,                  // $20 bytes_transferred
		nullableJSON(metadataJSON),        // $21 metadata
	)
	if err != nil {
		// Avoid spamming logs; the entry is dropped on DB error.
		// The channel will back-pressure the caller naturally.
		fmt.Printf("audit postgres: failed to insert audit event: %v\n", err)
	}
}

// classifyResource derives resource_type and resource_name from the API path.
func classifyResource(path string) (resourceType, resourceName string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return "", path
	}
	switch {
	case len(parts) >= 3 && parts[0] == "api" && parts[1] == "v1":
		switch parts[2] {
		case "buckets":
			if len(parts) >= 4 {
				resourceType = "bucket"
				resourceName = parts[3]
				if len(parts) >= 5 && parts[4] == "objects" {
					resourceType = "object"
					if len(parts) >= 6 {
						resourceName = strings.Join(parts[5:], "/")
					}
				}
			} else {
				resourceType = "bucket_list"
			}
		case "login", "logout", "session":
			resourceType = "session"
			resourceName = parts[2]
		default:
			resourceType = "api"
			resourceName = path
		}
	default:
		resourceType = "api"
		resourceName = path
	}
	return resourceType, resourceName
}

func stringFromTags(tags map[string]interface{}, key string) string {
	if tags == nil {
		return ""
	}
	v, ok := tags[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullableInt(n int) interface{} {
	if n == 0 {
		return nil
	}
	return n
}

func nullableJSON(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

// maskDSN strips the password from a PostgreSQL DSN for safe display.
func maskDSN(dsn string) string {
	// Handle URL format: postgresql://user:password@host/db
	if idx := strings.Index(dsn, "@"); idx != -1 {
		prefix := dsn[:idx]
		if pwIdx := strings.LastIndex(prefix, ":"); pwIdx != -1 {
			return prefix[:pwIdx] + ":***" + dsn[idx:]
		}
	}
	return dsn
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	sensitiveParts := []string{
		"authorization",
		"token",
		"secret",
		"password",
		"passwd",
		"cookie",
		"apikey",
		"api_key",
		"access_key",
		"secret_key",
		"credential",
	}
	for _, p := range sensitiveParts {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

func deriveAction(method, requestPath, objectKey string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	pathValue := strings.TrimSpace(requestPath)
	lowerPath := strings.ToLower(pathValue)

	switch {
	case strings.Contains(lowerPath, "/login") && m == "POST":
		return "login"
	case strings.Contains(lowerPath, "/logout"):
		return "logout"
	case strings.Contains(lowerPath, "/oauth/callback"):
		return "oauth_callback"
	case strings.Contains(lowerPath, "/objects/upload-directory"):
		return "upload_directory"
	case strings.Contains(lowerPath, "/objects/upload"):
		return "upload"
	case strings.Contains(lowerPath, "/objects/download-directory"):
		return "download_directory"
	case strings.Contains(lowerPath, "/objects/download-multiple"):
		return "download_multiple"
	case strings.Contains(lowerPath, "/objects/download"):
		return "download"
	case strings.Contains(lowerPath, "/objects/metadata"):
		return "get_metadata"
	case strings.Contains(lowerPath, "/objects/share"):
		return "share"
	case strings.Contains(lowerPath, "/objects/tags"):
		if m == "PUT" {
			return "put_object_tags"
		}
		if m == "GET" {
			return "get_object_tags"
		}
		return "object_tags"
	case strings.Contains(lowerPath, "/objects/restore"):
		return "restore_object"
	case strings.Contains(lowerPath, "/delete-objects"):
		return "delete_multiple_objects"
	case strings.Contains(lowerPath, "/objects") && m == "DELETE":
		return "delete_object"
	case strings.Contains(lowerPath, "/objects") && m == "GET":
		if objectKey != "" {
			return "get_object"
		}
		return "list_objects"
	}

	bucket := parseBucketFromPath(pathValue)
	if bucket == "" {
		switch m {
		case "GET":
			return "read"
		case "POST":
			return "create"
		case "PUT", "PATCH":
			return "update"
		case "DELETE":
			return "delete"
		default:
			return strings.ToLower(m)
		}
	}

	if objectKey != "" {
		switch m {
		case "GET", "HEAD":
			return "get_object"
		case "PUT", "POST":
			return "upload"
		case "DELETE":
			return "delete_object"
		default:
			return "object_action"
		}
	}

	switch m {
	case "GET", "HEAD":
		return "list"
	case "POST":
		return "create_bucket"
	case "PUT", "PATCH":
		return "update_bucket"
	case "DELETE":
		return "delete_bucket"
	default:
		return strings.ToLower(m)
	}
}

func isObjectAction(action string) bool {
	switch action {
	case "upload", "upload_directory", "get_object", "delete_object", "share", "get_metadata", "restore_object", "put_object_tags", "get_object_tags", "object_tags":
		return true
	default:
		return false
	}
}

func parseBucketAndObject(entry audit.Entry) (string, string) {
	requestPath := strings.TrimSpace(entry.API.Path)
	parts := strings.Split(strings.Trim(requestPath, "/"), "/")
	if len(parts) < 4 {
		return "", queryObjectKey(entry)
	}
	reservedObjectSegments := map[string]bool{
		"upload":             true,
		"upload-directory":   true,
		"download":           true,
		"download-directory": true,
		"download-multiple":  true,
		"metadata":           true,
		"share":              true,
		"tags":               true,
		"restore":            true,
	}
	for i := 0; i < len(parts); i++ {
		if parts[i] == "buckets" && i+1 < len(parts) {
			bucket := parts[i+1]
			if i+2 < len(parts) && parts[i+2] == "objects" && i+3 < len(parts) {
				next := parts[i+3]
				if reservedObjectSegments[next] {
					return bucket, queryObjectKey(entry)
				}
				return bucket, strings.Join(parts[i+3:], "/")
			}
			return bucket, queryObjectKey(entry)
		}
	}
	return "", queryObjectKey(entry)
}

func parseBucketFromPath(requestPath string) string {
	parts := strings.Split(strings.Trim(requestPath, "/"), "/")
	for i := 0; i < len(parts); i++ {
		if parts[i] == "buckets" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func queryObjectKey(entry audit.Entry) string {
	if entry.ReqQuery == nil {
		return ""
	}
	return firstNonEmpty(entry.ReqQuery["object"], entry.ReqQuery["name"], entry.ReqQuery["key"], entry.ReqQuery["prefix"], entry.ReqQuery["path"])
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func ensureSchema(db *sql.DB) error {
	ddl := []string{
		`CREATE TABLE IF NOT EXISTS audit_events (
			id BIGSERIAL PRIMARY KEY,
			timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
			user_id VARCHAR(255),
			user_email VARCHAR(255),
			session_id VARCHAR(255),
			tenant_id VARCHAR(255),
			action VARCHAR(100) NOT NULL,
			resource_type VARCHAR(100),
			resource_name VARCHAR(500),
			bucket_name VARCHAR(255),
			object_key TEXT,
			source_ip VARCHAR(45),
			user_agent TEXT,
			request_id VARCHAR(255),
			status VARCHAR(50) NOT NULL,
			error_message TEXT,
			request_method VARCHAR(10),
			request_path TEXT,
			response_code INTEGER,
			duration_ms INTEGER,
			bytes_transferred BIGINT,
			metadata JSONB,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_events(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_tenant_id ON audit_events(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_session_id ON audit_events(session_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_events(status)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_bucket_name ON audit_events(bucket_name)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_resource_type ON audit_events(resource_type)`,
	}
	for _, stmt := range ddl {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func ensureDatabaseExists(dsn string) (bool, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return false, err
	}
	dbName := strings.TrimPrefix(path.Clean(u.Path), "/")
	if dbName == "" || dbName == "." {
		return false, errors.New("missing database name in DSN")
	}

	adminURL := *u
	adminURL.Path = "/postgres"
	adminDB, err := sql.Open("postgres", adminURL.String())
	if err != nil {
		return false, err
	}
	defer adminDB.Close()

	if err = adminDB.Ping(); err != nil {
		return false, err
	}

	var exists bool
	err = adminDB.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, dbName).Scan(&exists)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}

	q := fmt.Sprintf(`CREATE DATABASE "%s"`, strings.ReplaceAll(dbName, `"`, `""`))
	if _, err = adminDB.Exec(q); err != nil {
		return false, err
	}
	return true, nil
}

func normalizeDSN(dsn string) string {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return trimmed
	}

	// URL DSN: postgres://user:pass@host:5432/db?...
	if u, err := url.Parse(trimmed); err == nil && u.Scheme != "" {
		q := u.Query()
		if q.Get("sslmode") == "" {
			q.Set("sslmode", "disable")
			u.RawQuery = q.Encode()
		}
		return u.String()
	}

	// Keyword DSN: host=... user=... dbname=...
	if !strings.Contains(strings.ToLower(trimmed), "sslmode=") {
		return trimmed + " sslmode=disable"
	}

	return trimmed
}

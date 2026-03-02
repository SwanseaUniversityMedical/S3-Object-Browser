-- Initialize audit database for object-browser
-- This script creates the audit_logs database and necessary tables

-- Create the audit_logs database
CREATE DATABASE audit_logs;

-- Connect to the audit_logs database
\c audit_logs;

-- Create audit_events table to store all audit logs
CREATE TABLE IF NOT EXISTS audit_events (
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
);

-- Create indexes for common query patterns
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp DESC);
CREATE INDEX idx_audit_user_id ON audit_events(user_id);
CREATE INDEX idx_audit_action ON audit_events(action);
CREATE INDEX idx_audit_tenant_id ON audit_events(tenant_id);
CREATE INDEX idx_audit_session_id ON audit_events(session_id);
CREATE INDEX idx_audit_status ON audit_events(status);
CREATE INDEX idx_audit_bucket_name ON audit_events(bucket_name);
CREATE INDEX idx_audit_resource_type ON audit_events(resource_type);

-- Create a view for failed operations
CREATE VIEW failed_operations AS
SELECT 
    id,
    timestamp,
    user_id,
    user_email,
    action,
    resource_type,
    resource_name,
    bucket_name,
    object_key,
    status,
    error_message,
    source_ip
FROM audit_events
WHERE status IN ('error', 'failed', 'denied')
ORDER BY timestamp DESC;

-- Create a view for high-value operations (delete, modify permissions, etc.)
CREATE VIEW critical_operations AS
SELECT 
    id,
    timestamp,
    user_id,
    user_email,
    action,
    resource_type,
    resource_name,
    bucket_name,
    object_key,
    status,
    source_ip,
    metadata
FROM audit_events
WHERE action IN ('delete', 'delete_bucket', 'put_bucket_policy', 'delete_object', 'restore_object')
ORDER BY timestamp DESC;

-- Grant permissions to the keycloak user (used by the application)
GRANT ALL PRIVILEGES ON DATABASE audit_logs TO keycloak;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO keycloak;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO keycloak;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO keycloak;

-- Ensure future tables/sequences are also granted
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO keycloak;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO keycloak;

-- Add a comment explaining the purpose
COMMENT ON TABLE audit_events IS 'Audit log for all object-browser operations';
COMMENT ON VIEW failed_operations IS 'View of all failed/denied operations for security monitoring';
COMMENT ON VIEW critical_operations IS 'View of high-value operations that require special attention';

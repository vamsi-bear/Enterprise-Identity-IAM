-- ============================================
-- ENTERPRISE IAM DATABASE
-- SecureSphere Technologies
-- ============================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================
-- USERS
-- ============================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    username VARCHAR(80) NOT NULL UNIQUE,

    email VARCHAR(255) NOT NULL UNIQUE,

    password_hash TEXT NOT NULL,

    first_name VARCHAR(100),

    last_name VARCHAR(100),

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    is_locked BOOLEAN NOT NULL DEFAULT FALSE,

    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    failed_login_attempts INTEGER NOT NULL DEFAULT 0,

    locked_until TIMESTAMPTZ,

    last_login_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ============================================
-- ROLES
-- ============================================

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name VARCHAR(100) NOT NULL UNIQUE,

    description TEXT,

    risk_level VARCHAR(20)
        NOT NULL DEFAULT 'LOW'
        CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    mfa_required BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ============================================
-- PERMISSIONS
-- ============================================

CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name VARCHAR(150) NOT NULL UNIQUE,

    resource VARCHAR(100) NOT NULL,

    action VARCHAR(100) NOT NULL,

    description TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(resource, action)
);


-- ============================================
-- USER ↔ ROLE
-- ============================================

CREATE TABLE user_roles (
    user_id UUID NOT NULL,

    role_id UUID NOT NULL,

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    assigned_by UUID,

    PRIMARY KEY(user_id, role_id),

    CONSTRAINT fk_user_roles_user
        FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_user_roles_role
        FOREIGN KEY(role_id)
        REFERENCES roles(id)
        ON DELETE CASCADE
);


-- ============================================
-- ROLE ↔ PERMISSION
-- ============================================

CREATE TABLE role_permissions (
    role_id UUID NOT NULL,

    permission_id UUID NOT NULL,

    granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY(role_id, permission_id),

    CONSTRAINT fk_role_permissions_role
        FOREIGN KEY(role_id)
        REFERENCES roles(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_role_permissions_permission
        FOREIGN KEY(permission_id)
        REFERENCES permissions(id)
        ON DELETE CASCADE
);


-- ============================================
-- GROUPS
-- ============================================

CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name VARCHAR(100) NOT NULL UNIQUE,

    description TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ============================================
-- GROUP MEMBERS
-- ============================================

CREATE TABLE group_members (
    group_id UUID NOT NULL,

    user_id UUID NOT NULL,

    added_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY(group_id, user_id),

    FOREIGN KEY(group_id)
        REFERENCES groups(id)
        ON DELETE CASCADE,

    FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);


-- ============================================
-- APPLICATIONS
-- ============================================

CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name VARCHAR(150) NOT NULL UNIQUE,

    description TEXT,

    application_type VARCHAR(50),

    url TEXT,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ============================================
-- APPLICATION PERMISSIONS
-- ============================================

CREATE TABLE application_permissions (
    application_id UUID NOT NULL,

    permission_id UUID NOT NULL,

    PRIMARY KEY(application_id, permission_id),

    FOREIGN KEY(application_id)
        REFERENCES applications(id)
        ON DELETE CASCADE,

    FOREIGN KEY(permission_id)
        REFERENCES permissions(id)
        ON DELETE CASCADE
);


-- ============================================
-- POLICIES
-- ============================================

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name VARCHAR(150) NOT NULL UNIQUE,

    description TEXT,

    effect VARCHAR(10) NOT NULL
        CHECK (effect IN ('ALLOW', 'DENY')),

    priority INTEGER NOT NULL DEFAULT 100,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_by UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ============================================
-- POLICY STATEMENTS
-- ============================================

CREATE TABLE policy_statements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    policy_id UUID NOT NULL,

    resource VARCHAR(200) NOT NULL,

    action VARCHAR(150) NOT NULL,

    condition JSONB,

    FOREIGN KEY(policy_id)
        REFERENCES policies(id)
        ON DELETE CASCADE
);


-- ============================================
-- MFA CREDENTIALS
-- ============================================

CREATE TABLE mfa_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL UNIQUE,

    secret_encrypted TEXT NOT NULL,

    algorithm VARCHAR(20) DEFAULT 'SHA1',

    digits INTEGER DEFAULT 6,

    period INTEGER DEFAULT 30,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    last_used_at TIMESTAMPTZ,

    FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);


-- ============================================
-- BACKUP CODES
-- ============================================

CREATE TABLE backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL,

    code_hash TEXT NOT NULL,

    used BOOLEAN NOT NULL DEFAULT FALSE,

    used_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);


-- ============================================
-- SESSIONS
-- ============================================

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL,

    token_hash TEXT NOT NULL UNIQUE,

    ip_address INET,

    user_agent TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    expires_at TIMESTAMPTZ NOT NULL,

    revoked_at TIMESTAMPTZ,

    FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);


-- ============================================
-- LOGIN ATTEMPTS
-- ============================================

CREATE TABLE login_attempts (
    id BIGSERIAL PRIMARY KEY,

    user_id UUID,

    username_attempted VARCHAR(80),

    ip_address INET,

    user_agent TEXT,

    success BOOLEAN NOT NULL,

    failure_reason VARCHAR(200),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);


-- ============================================
-- AUDIT LOGS
-- ============================================

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,

    user_id UUID,

    action VARCHAR(150) NOT NULL,

    resource VARCHAR(200),

    resource_id VARCHAR(200),

    result VARCHAR(30) NOT NULL
        CHECK (result IN ('SUCCESS', 'FAILED', 'DENIED')),

    risk_level VARCHAR(20) NOT NULL
        CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    ip_address INET,

    user_agent TEXT,

    metadata JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);


-- ============================================
-- SECURITY EVENTS
-- ============================================

CREATE TABLE security_events (
    id BIGSERIAL PRIMARY KEY,

    user_id UUID,

    event_type VARCHAR(100) NOT NULL,

    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    description TEXT,

    source_ip INET,

    metadata JSONB,

    resolved BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    resolved_at TIMESTAMPTZ,

    FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);
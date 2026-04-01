-- ============================================================
--  ANTIGRAVITY — MySQL Schema
--  Run this in phpMyAdmin (XAMPP) or via: mysql -u root < antigravity_db.sql
--  Requires MySQL 8.0+ (ships with XAMPP 3.3+)
-- ============================================================

CREATE DATABASE IF NOT EXISTS antigravity
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE antigravity;

-- ============================================================
-- Table 1: vulnerabilities
-- Stores all parsed DAST / CSPM findings (ZAP, Burp, Nuclei, Prowler, Checkov)
-- full_data holds the complete UnifiedVulnerability JSON blob
-- ============================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              VARCHAR(36)     NOT NULL PRIMARY KEY COMMENT 'UUID v4',
    title           VARCHAR(512)    NOT NULL,
    severity        ENUM('critical','high','medium','low','info') NOT NULL DEFAULT 'info',
    priority_score  FLOAT           NOT NULL DEFAULT 0.0,
    status          ENUM('new','in_progress','remediated','false_positive','risk_accepted') NOT NULL DEFAULT 'new',
    scanner_source  VARCHAR(64)     NOT NULL,
    environment     VARCHAR(128)    DEFAULT 'unknown',
    full_data       JSON            NOT NULL COMMENT 'Full UnifiedVulnerability model serialized',
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_severity      (severity),
    INDEX idx_priority      (priority_score DESC),
    INDEX idx_status        (status),
    INDEX idx_scanner       (scanner_source),
    INDEX idx_created       (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table 2: assessment_sessions
-- Stores WAF Phase 1 assessment sessions + pillar scores + recommendations
-- ============================================================
CREATE TABLE IF NOT EXISTS assessment_sessions (
    id                  VARCHAR(36)     NOT NULL PRIMARY KEY COMMENT 'UUID v4 session ID',
    started_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at        DATETIME        DEFAULT NULL,
    workload_type       VARCHAR(256)    DEFAULT NULL,
    average_score       FLOAT           DEFAULT NULL,
    pillar_scores       JSON            DEFAULT NULL COMMENT 'Array of {pillar, score, maturity} objects',
    recommendations     JSON            DEFAULT NULL COMMENT 'Array of recommendation objects',
    executive_summary   TEXT            DEFAULT NULL,
    qa_log              JSON            DEFAULT NULL COMMENT 'Full Q&A transcript',
    conversation_history JSON           DEFAULT NULL,

    INDEX idx_started      (started_at DESC),
    INDEX idx_score        (average_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Table 3: api_keys
-- Hashed API keys for authenticating all /api/v1/* endpoints
-- ============================================================
CREATE TABLE IF NOT EXISTS api_keys (
    id              INT UNSIGNED    NOT NULL AUTO_INCREMENT PRIMARY KEY,
    key_hash        VARCHAR(128)    NOT NULL UNIQUE COMMENT 'SHA-256 hash of the raw key',
    label           VARCHAR(128)    NOT NULL COMMENT 'Human-readable label (e.g. client name)',
    is_active       TINYINT(1)      NOT NULL DEFAULT 1,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at    DATETIME        DEFAULT NULL,
    requests_count  BIGINT UNSIGNED NOT NULL DEFAULT 0,

    INDEX idx_key_hash (key_hash),
    INDEX idx_active   (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Seed: Insert a default dev API key (raw value: dev-test-key-antigravity)
-- SHA-256 of "dev-test-key-antigravity"
-- IMPORTANT: Replace this with a real key in production!
-- ============================================================
INSERT IGNORE INTO api_keys (key_hash, label, is_active)
VALUES (
    SHA2('dev-test-key-antigravity', 256),
    'Default Dev Key - CHANGE IN PRODUCTION',
    1
);

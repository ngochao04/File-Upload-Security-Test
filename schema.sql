-- =====================================================
-- FILE UPLOAD SECURITY - PostgreSQL Schema
-- =====================================================

-- Create database (run as superuser)
CREATE DATABASE file_security_db;

-- Connect to the database then run below:

-- File records table
CREATE TABLE IF NOT EXISTS file_records (
    id               BIGSERIAL PRIMARY KEY,
    original_name    VARCHAR(500)  NOT NULL,
    sanitized_name   VARCHAR(500)  NOT NULL,
    stored_name      VARCHAR(600)  NOT NULL UNIQUE,
    file_path        TEXT          NOT NULL,
    file_size        BIGINT        NOT NULL,
    mime_type        VARCHAR(200)  NOT NULL,
    extension        VARCHAR(50),
    upload_status    VARCHAR(20)   NOT NULL CHECK (upload_status IN ('SUCCESS', 'REJECTED', 'QUARANTINED')),
    rejection_reason TEXT,
    uploaded_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
    uploader_ip      VARCHAR(100)
);

-- Indexes for common queries
CREATE INDEX idx_file_records_status     ON file_records(upload_status);
CREATE INDEX idx_file_records_uploaded   ON file_records(uploaded_at DESC);
CREATE INDEX idx_file_records_mime       ON file_records(mime_type);
CREATE INDEX idx_file_records_extension  ON file_records(extension);

-- View: upload summary
CREATE OR REPLACE VIEW upload_summary AS
SELECT
    upload_status,
    COUNT(*)                          AS total,
    SUM(file_size)                    AS total_bytes,
    ROUND(AVG(file_size))             AS avg_bytes,
    MAX(uploaded_at)                  AS last_upload
FROM file_records
GROUP BY upload_status;

-- View: rejection reasons breakdown
CREATE OR REPLACE VIEW rejection_summary AS
SELECT
    rejection_reason,
    COUNT(*) AS total
FROM file_records
WHERE upload_status = 'REJECTED'
GROUP BY rejection_reason
ORDER BY total DESC;

-- Sample query: show all rejected files
-- SELECT id, original_name, rejection_reason, uploaded_at, uploader_ip
-- FROM file_records
-- WHERE upload_status = 'REJECTED'
-- ORDER BY uploaded_at DESC;

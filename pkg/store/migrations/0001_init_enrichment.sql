-- 0001_init_enrichment.sql
-- Creates the enrichment_records table used to persist KEV + EPSS results.
--
-- Keyed by CVE (not an autoincrement ID) so that a future "findings" table
-- (image scans / SBOM components) can join on cve without needing a
-- migration to introduce a foreign key relationship.

CREATE TABLE IF NOT EXISTS enrichment_records (
    cve                     TEXT PRIMARY KEY,

    in_kev                  BOOLEAN NOT NULL DEFAULT 0,
    kev_vulnerability_name  TEXT,
    kev_date_added          TEXT,
    kev_due_date            TEXT,
    kev_required_action     TEXT,

    epss_score              REAL,
    epss_percentile         REAL,

    enriched                BOOLEAN NOT NULL DEFAULT 0,
    warning                 TEXT,

    enriched_at             TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_enrichment_records_in_kev
    ON enrichment_records (in_kev);


// Package store provides persistence and history for scan results.
//
// It currently persists enrichment.ThreatData (EPSS + KEV) keyed by CVE.
// The schema is deliberately scoped to that today, but the "cve" column is
// a natural key so a future findings/SBOM table can join against it without
// requiring a migration to introduce the relationship.
package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // registers the "sqlite" driver, pure Go, no CGO

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/enrichment"
)

// Store persists enrichment.ThreatData records to a SQLite database.
type Store struct {
	db *sql.DB
}

// New opens (creating if necessary) a SQLite database at dbPath and applies
// any pending migrations. Use ":memory:" for an ephemeral, process-local
// database, handy in tests.
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// SQLite only supports one writer at a time; a single connection avoids
	// "database is locked" errors under concurrent access from this process.
	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &Store{db: db}, nil
}

// Close releases the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// SaveThreatData upserts a single enrichment record, keyed by CVE.
func (s *Store) SaveThreatData(ctx context.Context, td enrichment.ThreatData) error {
	kevName, kevDateAdded, kevDueDate, kevRequiredAction := kevColumns(td)

	_, err := s.db.ExecContext(ctx, upsertSQL,
		td.CVE, td.InKEV, kevName, kevDateAdded, kevDueDate, kevRequiredAction,
		td.EPSSScore, td.Percentile, td.Enriched, nullIfEmpty(td.Warning), td.EnrichedAt,
	)
	if err != nil {
		return fmt.Errorf("saving enrichment record for %s: %w", td.CVE, err)
	}
	return nil
}

// SaveAll upserts every record in results within a single transaction, so a
// batch either fully lands or fully rolls back.
func (s *Store) SaveAll(ctx context.Context, results map[string]enrichment.ThreatData) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	defer tx.Rollback() // no-op once committed

	stmt, err := tx.PrepareContext(ctx, upsertSQL)
	if err != nil {
		return fmt.Errorf("preparing batch upsert: %w", err)
	}
	defer stmt.Close()

	for _, td := range results {
		kevName, kevDateAdded, kevDueDate, kevRequiredAction := kevColumns(td)

		if _, err := stmt.ExecContext(ctx,
			td.CVE, td.InKEV, kevName, kevDateAdded, kevDueDate, kevRequiredAction,
			td.EPSSScore, td.Percentile, td.Enriched, nullIfEmpty(td.Warning), td.EnrichedAt,
		); err != nil {
			return fmt.Errorf("saving enrichment record for %s: %w", td.CVE, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing batch upsert: %w", err)
	}
	return nil
}

// GetThreatData returns the persisted record for a CVE, if one exists.
func (s *Store) GetThreatData(ctx context.Context, cve string) (enrichment.ThreatData, bool, error) {
	row := s.db.QueryRowContext(ctx, selectSQL+` WHERE cve = ?`, cve)

	td, err := scanThreatData(row)
	if err == sql.ErrNoRows {
		return enrichment.ThreatData{}, false, nil
	}
	if err != nil {
		return enrichment.ThreatData{}, false, fmt.Errorf("reading enrichment record for %s: %w", cve, err)
	}
	return td, true, nil
}

// ListInKEV returns every persisted record currently flagged as being in the
// CISA KEV catalog. This is an example of the kind of query the schema is
// meant to support once there's more than one caller of this store.
func (s *Store) ListInKEV(ctx context.Context) ([]enrichment.ThreatData, error) {
	rows, err := s.db.QueryContext(ctx, selectSQL+` WHERE in_kev = 1 ORDER BY cve`)
	if err != nil {
		return nil, fmt.Errorf("listing KEV records: %w", err)
	}
	defer rows.Close()

	var results []enrichment.ThreatData
	for rows.Next() {
		td, err := scanThreatData(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning KEV record: %w", err)
		}
		results = append(results, td)
	}
	return results, rows.Err()
}

const (
	selectSQL = `
		SELECT cve, in_kev, kev_vulnerability_name, kev_date_added, kev_due_date,
		       kev_required_action, epss_score, epss_percentile, enriched, warning, enriched_at
		FROM enrichment_records`

	upsertSQL = `
		INSERT INTO enrichment_records (
			cve, in_kev, kev_vulnerability_name, kev_date_added, kev_due_date,
			kev_required_action, epss_score, epss_percentile, enriched, warning, enriched_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cve) DO UPDATE SET
			in_kev                 = excluded.in_kev,
			kev_vulnerability_name = excluded.kev_vulnerability_name,
			kev_date_added         = excluded.kev_date_added,
			kev_due_date           = excluded.kev_due_date,
			kev_required_action    = excluded.kev_required_action,
			epss_score             = excluded.epss_score,
			epss_percentile        = excluded.epss_percentile,
			enriched               = excluded.enriched,
			warning                = excluded.warning,
			enriched_at            = excluded.enriched_at`
)

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanThreatData(row rowScanner) (enrichment.ThreatData, error) {
	var (
		td                                                   enrichment.ThreatData
		inKEV                                                bool
		kevName, kevDateAdded, kevDueDate, kevRequiredAction sql.NullString
		warning                                              sql.NullString
	)

	if err := row.Scan(
		&td.CVE, &inKEV, &kevName, &kevDateAdded, &kevDueDate, &kevRequiredAction,
		&td.EPSSScore, &td.Percentile, &td.Enriched, &warning, &td.EnrichedAt,
	); err != nil {
		return enrichment.ThreatData{}, err
	}

	td.InKEV = inKEV
	td.Warning = warning.String
	if inKEV {
		td.KEVDetails = &enrichment.KEVRecord{
			VulnerabilityName: kevName.String,
			DateAdded:         kevDateAdded.String,
			DueDate:           kevDueDate.String,
			RequiredAction:    kevRequiredAction.String,
		}
	}

	return td, nil
}

func kevColumns(td enrichment.ThreatData) (name, dateAdded, dueDate, requiredAction sql.NullString) {
	if td.KEVDetails == nil {
		return
	}
	name = sql.NullString{String: td.KEVDetails.VulnerabilityName, Valid: true}
	dateAdded = sql.NullString{String: td.KEVDetails.DateAdded, Valid: true}
	dueDate = sql.NullString{String: td.KEVDetails.DueDate, Valid: true}
	requiredAction = sql.NullString{String: td.KEVDetails.RequiredAction, Valid: true}
	return
}

func nullIfEmpty(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

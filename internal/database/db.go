package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/0x-singularity/astra-threat-feed/internal/ioc"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

type Stats struct {
	TotalIOCs    int
	ByType       map[string]int
	BySource     map[string]int
	LastSyncedAt *time.Time
}

func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("enabling WAL mode: %w", err)
	}
	d := &DB{conn: conn}
	if err := d.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) Close() error {
	return d.conn.Close()
}

func (d *DB) migrate() error {
	_, err := d.conn.Exec(`
		CREATE TABLE IF NOT EXISTS iocs (
			id         INTEGER  PRIMARY KEY AUTOINCREMENT,
			value      TEXT     NOT NULL,
			type       TEXT     NOT NULL,
			source     TEXT     NOT NULL,
			comment    TEXT     NOT NULL DEFAULT '',
			tags       TEXT     NOT NULL DEFAULT '[]',
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(value, type)
		);
		CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
		CREATE INDEX IF NOT EXISTS idx_iocs_type   ON iocs(type);

		CREATE TABLE IF NOT EXISTS feed_events (
			feed_name  TEXT     PRIMARY KEY,
			event_uuid TEXT     NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS sync_log (
			id        INTEGER  PRIMARY KEY AUTOINCREMENT,
			feed_name TEXT     NOT NULL,
			count     INTEGER  NOT NULL DEFAULT 0,
			status    TEXT     NOT NULL,
			error     TEXT     NOT NULL DEFAULT '',
			synced_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return fmt.Errorf("migrating schema: %w", err)
	}
	return nil
}

func (d *DB) UpsertIOCs(items []ioc.IOC) (int, error) {
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO iocs (value, type, source, comment, tags, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(value, type) DO UPDATE SET
			last_seen = excluded.last_seen,
			comment   = CASE WHEN excluded.comment != '' THEN excluded.comment ELSE comment END
	`)
	if err != nil {
		return 0, fmt.Errorf("preparing statement: %w", err)
	}
	defer stmt.Close()

	for _, item := range items {
		tags, _ := json.Marshal(item.Tags)
		seen := item.Seen
		if seen.IsZero() {
			seen = time.Now().UTC()
		}
		if _, err := stmt.Exec(item.Value, item.Type, item.Source, item.Comment, string(tags), seen, seen); err != nil {
			return 0, fmt.Errorf("upserting IOC %q: %w", item.Value, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing transaction: %w", err)
	}
	return len(items), nil
}

func (d *DB) GetIOCsBySource(source string) ([]ioc.IOC, error) {
	rows, err := d.conn.Query(`
		SELECT value, type, source, comment, tags, last_seen
		FROM iocs
		WHERE source = ?
		ORDER BY last_seen DESC
	`, source)
	if err != nil {
		return nil, fmt.Errorf("querying IOCs for source %q: %w", source, err)
	}
	defer rows.Close()
	return scanIOCs(rows)
}

func (d *DB) GetDistinctSources() ([]string, error) {
	rows, err := d.conn.Query(`SELECT DISTINCT source FROM iocs ORDER BY source`)
	if err != nil {
		return nil, fmt.Errorf("querying sources: %w", err)
	}
	defer rows.Close()

	var sources []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}
	return sources, rows.Err()
}

func (d *DB) GetOrCreateEventUUID(feedName string) (string, error) {
	var id string
	err := d.conn.QueryRow(`SELECT event_uuid FROM feed_events WHERE feed_name = ?`, feedName).Scan(&id)
	if err == sql.ErrNoRows {
		id = uuid.New().String()
		if _, err := d.conn.Exec(`INSERT INTO feed_events (feed_name, event_uuid) VALUES (?, ?)`, feedName, id); err != nil {
			return "", fmt.Errorf("storing event UUID: %w", err)
		}
		return id, nil
	}
	if err != nil {
		return "", fmt.Errorf("querying event UUID: %w", err)
	}
	return id, nil
}

func (d *DB) LogSync(feedName string, count int, status, errMsg string) error {
	_, err := d.conn.Exec(
		`INSERT INTO sync_log (feed_name, count, status, error) VALUES (?, ?, ?, ?)`,
		feedName, count, status, errMsg,
	)
	return err
}

func (d *DB) Stats() (*Stats, error) {
	s := &Stats{
		ByType:   make(map[string]int),
		BySource: make(map[string]int),
	}

	if err := d.conn.QueryRow(`SELECT COUNT(*) FROM iocs`).Scan(&s.TotalIOCs); err != nil {
		return nil, err
	}

	typeRows, err := d.conn.Query(`SELECT type, COUNT(*) FROM iocs GROUP BY type`)
	if err != nil {
		return nil, err
	}
	defer typeRows.Close()
	for typeRows.Next() {
		var t string
		var n int
		if err := typeRows.Scan(&t, &n); err != nil {
			return nil, err
		}
		s.ByType[t] = n
	}

	srcRows, err := d.conn.Query(`SELECT source, COUNT(*) FROM iocs GROUP BY source ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer srcRows.Close()
	for srcRows.Next() {
		var src string
		var n int
		if err := srcRows.Scan(&src, &n); err != nil {
			return nil, err
		}
		s.BySource[src] = n
	}

	var lastSync sql.NullTime
	if err := d.conn.QueryRow(`SELECT MAX(synced_at) FROM sync_log WHERE status = 'ok'`).Scan(&lastSync); err == nil && lastSync.Valid {
		s.LastSyncedAt = &lastSync.Time
	}

	return s, nil
}

func scanIOCs(rows *sql.Rows) ([]ioc.IOC, error) {
	var result []ioc.IOC
	for rows.Next() {
		var item ioc.IOC
		var tagsJSON string
		var seen time.Time
		if err := rows.Scan(&item.Value, &item.Type, &item.Source, &item.Comment, &tagsJSON, &seen); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tagsJSON), &item.Tags)
		item.Seen = seen
		result = append(result, item)
	}
	return result, rows.Err()
}

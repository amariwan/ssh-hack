//go:build sched
// +build sched

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/amariwan/ssh-hack/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

// TrendStorage stores historical scan results
type TrendStorage struct {
	db *sql.DB
}

// NewTrendStorage creates or opens SQLite database
func NewTrendStorage(path string) (*TrendStorage, error) {
	if path == "" {
		path = "ssh-audit-trends.db"
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &TrendStorage{db: db}
	if err := storage.initSchema(); err != nil {
		return nil, err
	}

	return storage, nil
}

// initSchema creates tables if not exist
func (s *TrendStorage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scan_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL UNIQUE,
		start_time TIMESTAMP NOT NULL,
		end_time TIMESTAMP NOT NULL,
		total_hosts INTEGER,
		total_findings INTEGER,
		critical_count INTEGER,
		high_count INTEGER,
		medium_count INTEGER,
		low_count INTEGER,
		overall_score REAL,
		report_json TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_start_time ON scan_history(start_time);
	CREATE INDEX IF NOT EXISTS idx_scan_id ON scan_history(scan_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// SaveReport stores a report in the database
func (s *TrendStorage) SaveReport(report *models.Report) error {
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	query := `
	INSERT INTO scan_history (
		scan_id, start_time, end_time, total_hosts, total_findings,
		critical_count, high_count, medium_count, low_count, overall_score, report_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(scan_id) DO UPDATE SET
		end_time = excluded.end_time,
		total_hosts = excluded.total_hosts,
		total_findings = excluded.total_findings,
		report_json = excluded.report_json
	`

	_, err = s.db.Exec(query,
		report.Metadata.ScanID,
		report.Metadata.StartTime,
		report.Metadata.EndTime,
		report.Summary.TotalHosts,
		report.Summary.TotalFindings,
		report.Summary.FindingsBySeverity[models.SeverityCritical],
		report.Summary.FindingsBySeverity[models.SeverityHigh],
		report.Summary.FindingsBySeverity[models.SeverityMedium],
		report.Summary.FindingsBySeverity[models.SeverityLow],
		calculateScore(report),
		string(reportJSON),
	)

	return err
}

// GetLatestReport retrieves most recent scan
func (s *TrendStorage) GetLatestReport() (*models.Report, error) {
	var reportJSON string
	query := `SELECT report_json FROM scan_history ORDER BY start_time DESC LIMIT 1`

	err := s.db.QueryRow(query).Scan(&reportJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var report models.Report
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		return nil, err
	}

	return &report, nil
}

// GetTrend returns score history for charting
func (s *TrendStorage) GetTrend(days int) ([]TrendPoint, error) {
	query := `
	SELECT start_time, overall_score, total_findings
	FROM scan_history
	WHERE start_time > datetime('now', '-' || ? || ' days')
	ORDER BY start_time ASC
	`

	rows, err := s.db.Query(query, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TrendPoint
	for rows.Next() {
		var p TrendPoint
		var ts string
		if err := rows.Scan(&ts, &p.Score, &p.Findings); err != nil {
			return nil, err
		}
		p.Timestamp, _ = time.Parse(time.RFC3339, ts)
		points = append(points, p)
	}

	return points, rows.Err()
}

// TrendPoint represents a point in time series
type TrendPoint struct {
	Timestamp time.Time
	Score     float64
	Findings  int
}

// Close closes the database
func (s *TrendStorage) Close() error {
	return s.db.Close()
}

func calculateScore(report *models.Report) float64 {
	if report.Summary.TotalHosts == 0 {
		return 100.0
	}

	weights := map[models.SeverityLevel]float64{
		models.SeverityCritical: 10.0,
		models.SeverityHigh:     5.0,
		models.SeverityMedium:   2.0,
		models.SeverityLow:      1.0,
	}

	totalRisk := 0.0
	for sev, count := range report.Summary.FindingsBySeverity {
		totalRisk += float64(count) * weights[sev]
	}

	score := 100.0 - (totalRisk / float64(report.Summary.TotalHosts))
	if score < 0 {
		score = 0
	}
	return score
}

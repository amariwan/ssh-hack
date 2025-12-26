//go:build sched
// +build sched

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amariwan/ssh-hack/internal/models"
	"github.com/amariwan/ssh-hack/internal/util"
	"github.com/robfig/cron/v3"
)

// SchedulerConfig holds scheduling parameters
type SchedulerConfig struct {
	CronExpr        string
	SlackWebhook    string
	EmailRecipients []string // Stub for future
	AlertThreshold  float64  // Alert if score drops >10%
	StoragePath     string   // SQLite DB for trend tracking
}

// Scheduler manages periodic scans
type Scheduler struct {
	config     SchedulerConfig
	cron       *cron.Cron
	logger     util.Logger
	lastReport *models.Report
	storage    *TrendStorage
}

// NewScheduler creates a scheduler
func NewScheduler(config SchedulerConfig, logger util.Logger) (*Scheduler, error) {
	storage, err := NewTrendStorage(config.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to init storage: %w", err)
	}

	return &Scheduler{
		config:  config,
		cron:    cron.New(cron.WithSeconds()),
		logger:  logger,
		storage: storage,
	}, nil
}

// Start begins scheduled scans
func (s *Scheduler) Start(ctx context.Context) error {
	s.logger.Info("Starting scheduler", "cron", s.config.CronExpr)

	// Add scan job
	_, err := s.cron.AddFunc(s.config.CronExpr, func() {
		s.runScheduledScan(ctx)
	})
	if err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	s.cron.Start()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case <-ctx.Done():
		s.logger.Info("Context cancelled, shutting down scheduler")
	case sig := <-sigChan:
		s.logger.Info("Received signal, shutting down scheduler", "signal", sig)
	}

	// Graceful shutdown
	ctx := s.cron.Stop()
	<-ctx.Done()
	s.logger.Info("Scheduler stopped gracefully")

	return nil
}

// runScheduledScan executes a scan and checks for alerts
func (s *Scheduler) runScheduledScan(ctx context.Context) {
	s.logger.Info("Running scheduled scan", "time", time.Now().Format(time.RFC3339))

	// Run audit (reuse runAudit from main.go)
	report, err := executeAudit(ctx)
	if err != nil {
		s.logger.Error("Scheduled scan failed", "error", err)
		s.sendAlert(fmt.Sprintf("Scan failed: %v", err), nil)
		return
	}

	// Store results
	if err := s.storage.SaveReport(report); err != nil {
		s.logger.Error("Failed to save report", "error", err)
	}

	// Check for alerts
	s.checkAlerts(report)
	s.lastReport = report
}

// checkAlerts compares current report with previous
func (s *Scheduler) checkAlerts(currentReport *models.Report) {
	if s.lastReport == nil {
		return // No baseline yet
	}

	// Calculate risk score drop
	prevScore := s.calculateOverallScore(s.lastReport)
	currScore := s.calculateOverallScore(currentReport)
	scoreDrop := (prevScore - currScore) / prevScore * 100

	s.logger.Info("Score comparison", "previous", prevScore, "current", currScore, "drop_pct", scoreDrop)

	if scoreDrop > s.config.AlertThreshold {
		msg := fmt.Sprintf("⚠️ Security score dropped by %.1f%% (%.1f → %.1f)\n"+
			"Critical findings: %d\n"+
			"High findings: %d",
			scoreDrop, prevScore, currScore,
			currentReport.Summary.FindingsBySeverity[models.SeverityCritical],
			currentReport.Summary.FindingsBySeverity[models.SeverityHigh])
		s.sendAlert(msg, currentReport)
	}
}

// calculateOverallScore computes aggregate score (100 - weighted risk)
func (s *Scheduler) calculateOverallScore(report *models.Report) float64 {
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

// sendAlert sends notification via configured channels
func (s *Scheduler) sendAlert(message string, report *models.Report) {
	if s.config.SlackWebhook != "" {
		s.sendSlackAlert(message, report)
	}
	// Email stub (future implementation)
	if len(s.config.EmailRecipients) > 0 {
		s.logger.Info("Email alert (stub)", "recipients", s.config.EmailRecipients)
	}
}

// sendSlackAlert posts to Slack webhook
func (s *Scheduler) sendSlackAlert(message string, report *models.Report) {
	payload := map[string]interface{}{
		"text": fmt.Sprintf("🔐 SSH Audit Alert\n\n%s", message),
	}

	if report != nil {
		payload["attachments"] = []map[string]interface{}{
			{
				"color": "danger",
				"fields": []map[string]interface{}{
					{"title": "Scan ID", "value": report.Metadata.ScanID, "short": true},
					{"title": "Total Hosts", "value": report.Summary.TotalHosts, "short": true},
					{"title": "Total Findings", "value": report.Summary.TotalFindings, "short": true},
				},
			},
		}
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(s.config.SlackWebhook, "application/json", bytes.NewReader(body))
	if err != nil {
		s.logger.Error("Slack alert failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.logger.Error("Slack webhook returned error", "status", resp.Status)
	} else {
		s.logger.Info("Slack alert sent successfully")
	}
}

// executeAudit wraps the main audit logic for scheduler
func executeAudit(ctx context.Context) (*models.Report, error) {
	// This would call the main runAudit logic
	// For now, return stub to avoid circular dependency
	// In real impl, refactor runAudit to be callable
	return nil, fmt.Errorf("executeAudit stub: refactor runAudit to package level")
}

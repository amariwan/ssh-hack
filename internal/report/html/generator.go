package html

import (
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/amariwan/ssh-hack/internal/models"
)

//go:embed dashboard.html
var dashboardTemplate string

// Generator creates HTML reports
type Generator struct {
	tmpl *template.Template
}

// NewGenerator creates an HTML report generator
func NewGenerator() (*Generator, error) {
	tmpl, err := template.New("dashboard").Funcs(template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"formatDuration": func(d time.Duration) string {
			return d.Round(time.Second).String()
		},
		// lower: lowercase helper used in template
		"lower": func(s string) string { return strings.ToLower(s) },
		// mulf/divf: float math helpers for percentage calculation
		"mulf": func(a, b float64) float64 { return a * b },
		"divf": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"severityColor": func(sev models.SeverityLevel) string {
			switch sev {
			case models.SeverityCritical:
				return "#dc3545"
			case models.SeverityHigh:
				return "#fd7e14"
			case models.SeverityMedium:
				return "#ffc107"
			case models.SeverityLow:
				return "#17a2b8"
			default:
				return "#6c757d"
			}
		},
		// riskClass returns base class without prefix; template adds 'risk-'
		"riskClass": func(score int) string {
			if score >= 80 {
				return "critical"
			} else if score >= 60 {
				return "high"
			} else if score >= 40 {
				return "medium"
			}
			return "low"
		},
		// sevCount returns the int count for a severity string (critical|high|medium|low|info)
		"sevCount": func(r *models.Report, s string) int {
			switch strings.ToLower(s) {
			case "critical":
				return r.Summary.FindingsBySeverity[models.SeverityCritical]
			case "high":
				return r.Summary.FindingsBySeverity[models.SeverityHigh]
			case "medium":
				return r.Summary.FindingsBySeverity[models.SeverityMedium]
			case "low":
				return r.Summary.FindingsBySeverity[models.SeverityLow]
			default:
				return r.Summary.FindingsBySeverity[models.SeverityInfo]
			}
		},
	}).Parse(dashboardTemplate)

	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	return &Generator{tmpl: tmpl}, nil
}

// Generate creates an HTML report file
func (g *Generator) Generate(report *models.Report, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	// Prepare template data
	data := prepareTemplateData(report)

	if err := g.tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// prepareTemplateData structures report for template
func prepareTemplateData(report *models.Report) map[string]interface{} {
	// Calculate overall health score
	overallScore := calculateHealthScore(report)

	// Group findings by host
	findingsByHost := make(map[string][]models.Finding)
	for _, finding := range report.Findings {
		key := fmt.Sprintf("%s:%d", finding.HostIP, finding.Port)
		findingsByHost[key] = append(findingsByHost[key], finding)
	}

	// Prepare severity distribution for chart
	severityData := []map[string]interface{}{
		{"label": "Critical", "value": report.Summary.FindingsBySeverity[models.SeverityCritical], "color": "#dc3545"},
		{"label": "High", "value": report.Summary.FindingsBySeverity[models.SeverityHigh], "color": "#fd7e14"},
		{"label": "Medium", "value": report.Summary.FindingsBySeverity[models.SeverityMedium], "color": "#ffc107"},
		{"label": "Low", "value": report.Summary.FindingsBySeverity[models.SeverityLow], "color": "#17a2b8"},
	}

	return map[string]interface{}{
		"Report":         report,
		"OverallScore":   overallScore,
		"FindingsByHost": findingsByHost,
		"SeverityData":   severityData,
		"GeneratedTime":  time.Now().Format(time.RFC1123),
	}
}

// calculateHealthScore computes 0-100 health score
func calculateHealthScore(report *models.Report) int {
	if report.Summary.TotalHosts == 0 {
		return 100
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

	return int(score)
}

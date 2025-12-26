package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/amariwan/ssh-hack/internal/models"
	"github.com/amariwan/ssh-hack/internal/report/html"
)

// Reporter generates reports in various formats
type Reporter interface {
	Generate(report *models.Report, outputPath string) error
}

// JSONReporter generates JSON reports
type JSONReporter struct{}

func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

func (r *JSONReporter) Generate(report *models.Report, outputPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return os.WriteFile(outputPath, data, 0644)
}

// MarkdownReporter generates Markdown reports
type MarkdownReporter struct{}

func NewMarkdownReporter() *MarkdownReporter {
	return &MarkdownReporter{}
}

func (r *MarkdownReporter) Generate(report *models.Report, outputPath string) error {
	var md strings.Builder

	// Header
	md.WriteString("# SSH Security Audit Report\n\n")
	md.WriteString(fmt.Sprintf("**Generated:** %s\n\n", report.GeneratedAt.Format(time.RFC3339)))
	md.WriteString(fmt.Sprintf("**Scan ID:** %s\n\n", report.Metadata.ScanID))
	md.WriteString(fmt.Sprintf("**Duration:** %s\n\n", report.Metadata.Duration))

	// Summary
	md.WriteString("## Executive Summary\n\n")
	md.WriteString(fmt.Sprintf("- **Total Hosts:** %d\n", report.Summary.TotalHosts))
	md.WriteString(fmt.Sprintf("- **Total Findings:** %d\n", report.Summary.TotalFindings))
	md.WriteString("\n### Findings by Severity\n\n")
	md.WriteString("| Severity | Count |\n")
	md.WriteString("|----------|-------|\n")
	for sev, count := range report.Summary.FindingsBySeverity {
		md.WriteString(fmt.Sprintf("| %s | %d |\n", sev, count))
	}
	md.WriteString("\n")

	// Key Metrics
	md.WriteString("### Key Security Metrics\n\n")
	md.WriteString(fmt.Sprintf("- **Hosts with Password Auth Enabled:** %d (%.1f%%)\n",
		report.Summary.PasswordAuthEnabled,
		float64(report.Summary.PasswordAuthEnabled)/float64(report.Summary.TotalHosts)*100))
	md.WriteString(fmt.Sprintf("- **Hosts with Root Login Permitted:** %d (%.1f%%)\n\n",
		report.Summary.RootLoginPermitted,
		float64(report.Summary.RootLoginPermitted)/float64(report.Summary.TotalHosts)*100))

	// Weak Crypto
	if len(report.Summary.WeakKexUsage) > 0 {
		md.WriteString("### Weak Kex Algorithms\n\n")
		md.WriteString("| Algorithm | Hosts |\n")
		md.WriteString("|-----------|-------|\n")
		for alg, count := range report.Summary.WeakKexUsage {
			md.WriteString(fmt.Sprintf("| `%s` | %d |\n", alg, count))
		}
		md.WriteString("\n")
	}

	if len(report.Summary.WeakCipherUsage) > 0 {
		md.WriteString("### Weak Ciphers\n\n")
		md.WriteString("| Cipher | Hosts |\n")
		md.WriteString("|--------|-------|\n")
		for cipher, count := range report.Summary.WeakCipherUsage {
			md.WriteString(fmt.Sprintf("| `%s` | %d |\n", cipher, count))
		}
		md.WriteString("\n")
	}

	// CVEs
	if len(report.Summary.CVECounts) > 0 {
		md.WriteString("### Common Vulnerabilities\n\n")
		md.WriteString("| CVE | Affected Hosts |\n")
		md.WriteString("|-----|----------------|\n")
		for cve, count := range report.Summary.CVECounts {
			md.WriteString(fmt.Sprintf("| %s | %d |\n", cve, count))
		}
		md.WriteString("\n")
	}

	// Detailed Findings
	md.WriteString("## Detailed Findings\n\n")
	findingsBySeverity := groupBySeverity(report.Findings)
	severityOrder := []models.SeverityLevel{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityInfo,
	}

	for _, sev := range severityOrder {
		findings, ok := findingsBySeverity[sev]
		if !ok || len(findings) == 0 {
			continue
		}

		md.WriteString(fmt.Sprintf("### %s (%d)\n\n", strings.ToUpper(string(sev)), len(findings)))
		for _, f := range findings {
			md.WriteString(fmt.Sprintf("#### %s\n\n", f.Title))
			md.WriteString(fmt.Sprintf("- **Host:** %s:%d\n", f.HostIP, f.Port))
			md.WriteString(fmt.Sprintf("- **Category:** %s\n", f.Category))
			md.WriteString(fmt.Sprintf("- **Risk Score:** %d/100\n", f.RiskScore))
			md.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))
			md.WriteString(fmt.Sprintf("- **Remediation:** %s\n", f.Remediation))
			if f.ImplementationType != "" && f.ImplementationType != models.ImplUnknown {
				md.WriteString(fmt.Sprintf("- **Implementation:** %s\n", f.ImplementationType))
			}
			if len(f.CVEs) > 0 {
				md.WriteString(fmt.Sprintf("- **CVEs:** %s\n", strings.Join(f.CVEs, ", ")))
			}
			if f.AnomalyDetails != nil {
				md.WriteString(fmt.Sprintf("- **Anomaly:** %s (observed: %.2f, z-score: %.2f)\n",
					f.AnomalyDetails.MetricName, f.AnomalyDetails.ObservedValue, f.AnomalyDetails.ZScore))
			}
			if f.RemediationScript != "" {
				md.WriteString("\n##### Remediation Script\n\n")
				md.WriteString("``````\n")
				md.WriteString(f.RemediationScript)
				md.WriteString("\n``````\n\n")
			}
			md.WriteString("\n")
		}
	}

	// Host Details
	md.WriteString("## Scanned Hosts\n\n")
	md.WriteString("| IP | Port | Version | Kex Algorithms | Ciphers |\n")
	md.WriteString("|----|------|---------|----------------|----------|\n")
	for _, host := range report.Hosts {
		md.WriteString(fmt.Sprintf("| %s | %d | %s | %d | %d |\n",
			host.Host.IP.String(),
			host.Host.Port,
			host.Version,
			len(host.KexAlgorithms),
			len(host.Ciphers.ClientToServer)))
	}

	return os.WriteFile(outputPath, []byte(md.String()), 0644)
}

// SARIFReporter generates SARIF format for CI/CD integration
type SARIFReporter struct{}

func NewSARIFReporter() *SARIFReporter {
	return &SARIFReporter{}
}

func (r *SARIFReporter) Generate(report *models.Report, outputPath string) error {
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "SSH Security Auditor",
						"version":        report.Metadata.ToolVersion,
						"informationUri": "https://github.com/amariwan/ssh-hack",
					},
				},
				"results": convertToSARIFResults(report.Findings),
			},
		},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	return os.WriteFile(outputPath, data, 0644)
}

func convertToSARIFResults(findings []models.Finding) []map[string]interface{} {
	var results []map[string]interface{}

	for _, f := range findings {
		result := map[string]interface{}{
			"ruleId": f.ID,
			"level":  sarifLevel(f.Severity),
			"message": map[string]interface{}{
				"text": f.Description,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": fmt.Sprintf("ssh://%s:%d", f.HostIP, f.Port),
						},
					},
				},
			},
		}

		if len(f.CVEs) > 0 {
			result["properties"] = map[string]interface{}{
				"cves": f.CVEs,
			}
		}

		results = append(results, result)
	}

	return results
}

func sarifLevel(severity models.SeverityLevel) string {
	switch severity {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	case models.SeverityLow, models.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// HTMLReporter generates HTML dashboard reports
type HTMLReporter struct {
	generator *html.Generator
}

func NewHTMLReporter() *HTMLReporter {
	gen, err := html.NewGenerator()
	if err != nil {
		// Fall back to a simple error - this shouldn't happen with embedded templates
		panic(fmt.Sprintf("failed to create HTML generator: %v", err))
	}
	return &HTMLReporter{generator: gen}
}

func (r *HTMLReporter) Generate(report *models.Report, outputPath string) error {
	return r.generator.Generate(report, outputPath)
}

// Helper functions
func groupBySeverity(findings []models.Finding) map[models.SeverityLevel][]models.Finding {
	grouped := make(map[models.SeverityLevel][]models.Finding)
	for _, f := range findings {
		grouped[f.Severity] = append(grouped[f.Severity], f)
	}
	return grouped
}

// GenerateSummary creates summary statistics from findings
func GenerateSummary(hosts []models.SSHInfo, findings []models.Finding) models.Summary {
	summary := models.Summary{
		TotalHosts:         len(hosts),
		TotalFindings:      len(findings),
		FindingsBySeverity: make(map[models.SeverityLevel]int),
		WeakKexUsage:       make(map[string]int),
		WeakCipherUsage:    make(map[string]int),
		WeakMACUsage:       make(map[string]int),
		CVECounts:          make(map[string]int),
	}

	for _, f := range findings {
		summary.FindingsBySeverity[f.Severity]++

		if f.Category == "kex" && (f.Severity == models.SeverityHigh || f.Severity == models.SeverityCritical) {
			summary.WeakKexUsage[extractAlgorithm(f.Title)]++
		}
		if f.Category == "cipher" && (f.Severity == models.SeverityHigh || f.Severity == models.SeverityCritical) {
			summary.WeakCipherUsage[extractAlgorithm(f.Title)]++
		}
		if f.Category == "mac" && (f.Severity == models.SeverityHigh || f.Severity == models.SeverityCritical) {
			summary.WeakMACUsage[extractAlgorithm(f.Title)]++
		}

		for _, cve := range f.CVEs {
			summary.CVECounts[cve]++
		}
	}

	// Count policy violations
	for _, host := range hosts {
		if host.Policy != nil {
			if host.Policy.PasswordAuthentication != nil && *host.Policy.PasswordAuthentication {
				summary.PasswordAuthEnabled++
			}
			if host.Policy.PermitRootLogin != "" && host.Policy.PermitRootLogin != "no" {
				summary.RootLoginPermitted++
			}
		}
	}

	return summary
}

func extractAlgorithm(title string) string {
	// Extract algorithm name from title like "Forbidden Cipher: 3des-cbc"
	parts := strings.Split(title, ": ")
	if len(parts) > 1 {
		return parts[1]
	}
	return title
}

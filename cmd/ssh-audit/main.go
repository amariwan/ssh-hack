package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/amariwan/ssh-hack/internal/analyze"
	"github.com/amariwan/ssh-hack/internal/models"
	"github.com/amariwan/ssh-hack/internal/net/scan"
	"github.com/amariwan/ssh-hack/internal/report"
	"github.com/amariwan/ssh-hack/internal/ssh/handshake"
	"github.com/amariwan/ssh-hack/internal/storage"
	"github.com/amariwan/ssh-hack/internal/util"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	version = "dev"

	// CLI flags
	allowlist       []string
	ports           []int
	concurrency     int
	timeout         int
	rateLimit       int
	dnsReverse      bool
	dryRun          bool
	authorized      bool
	baselineFile    string
	vulnsFile       string
	outputJSON      string
	outputMarkdown  string
	outputHTML      string
	outputSARIF     string
	failOnSeverity  string
	logLevel        string
	logFile         string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "ssh-audit",
		Short: "Enterprise SSH inventory and security auditing tool",
		Long: `ssh-audit discovers, analyzes, and hardens SSH infrastructure across networks.
		
Features:
- TCP-connect scanning (no raw packets)
- KEXINIT parsing and cipher analysis
- Policy auditing via sshd_config
- CVE mapping with offline database
- Risk scoring and baseline drift detection
- JSON, Markdown, SARIF, and HTML reporting`,
		Version: version,
		RunE:    run,
	}

	// Core flags
	rootCmd.Flags().StringSliceVar(&allowlist, "allowlist", []string{}, "Target CIDRs/IPs to scan (required)")
	rootCmd.Flags().IntSliceVar(&ports, "ports", []int{22}, "SSH ports to scan")
	rootCmd.Flags().IntVar(&concurrency, "concurrency", 100, "Concurrent workers")
	rootCmd.Flags().IntVar(&timeout, "timeout", 5, "Connection timeout (seconds)")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 500, "Requests per second")
	rootCmd.Flags().BoolVar(&dnsReverse, "dns-reverse", false, "Perform reverse DNS lookups")
	rootCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print targets without scanning")
	rootCmd.Flags().BoolVar(&authorized, "i-am-authorized", false, "Consent flag (required)")

	// Configuration
	rootCmd.Flags().StringVar(&baselineFile, "baseline", "configs/baseline.yml", "Security baseline file")
	rootCmd.Flags().StringVar(&vulnsFile, "vulns", "configs/vulns.yml", "Vulnerability database file")

	// Output
	rootCmd.Flags().StringVar(&outputJSON, "output-json", "", "Output JSON report path")
	rootCmd.Flags().StringVar(&outputMarkdown, "output-markdown", "", "Output Markdown report path")
	rootCmd.Flags().StringVar(&outputHTML, "output-html", "", "Output HTML dashboard path")
	rootCmd.Flags().StringVar(&outputSARIF, "output-sarif", "", "Output SARIF report path")

	// Control
	rootCmd.Flags().StringVar(&failOnSeverity, "fail-on", "", "Exit non-zero on severity (critical, high, medium, low)")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().StringVar(&logFile, "log-file", "", "Log file path (optional)")

	// Mark required flags
	rootCmd.MarkFlagRequired("allowlist")
	rootCmd.MarkFlagRequired("i-am-authorized")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Initialize logger
	logger, err := util.InitLogger(logLevel, logFile)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Validate authorization
	if !authorized {
		return fmt.Errorf("--i-am-authorized flag is required. Only scan networks you own or have explicit written permission to test")
	}

	logger.Info("Starting SSH audit", "version", version, "authorized", authorized)

	// Dry run: just print targets
	if dryRun {
		logger.Info("Dry run mode: listing targets without scanning")
		for _, target := range allowlist {
			for _, port := range ports {
				fmt.Printf("%s:%d\n", target, port)
			}
		}
		return nil
	}

	// Load security baseline
	logger.Info("Loading security baseline", "file", baselineFile)
	baseline, err := storage.LoadBaseline(baselineFile)
	if err != nil {
		logger.Warn("Failed to load baseline, using defaults", "error", err)
		baseline = getDefaultBaseline()
	}

	// Load vulnerability database
	logger.Info("Loading vulnerability database", "file", vulnsFile)
	vulnDB, err := storage.LoadVulnDatabase(vulnsFile)
	if err != nil {
		logger.Warn("Failed to load vulnerability database, using empty DB", "error", err)
		vulnDB = &storage.VulnDatabase{}
	}

	// Initialize scan context
	ctx := context.Background()
	scanID := uuid.New().String()
	startTime := time.Now()

	logger.Info("Starting scan", "scan_id", scanID, "targets", allowlist, "ports", ports)

	// Phase 1: Discovery
	scanner := scan.NewTCPScanner(concurrency, time.Duration(timeout)*time.Second, rateLimit, dnsReverse, logger)
	hosts, err := scanner.Scan(ctx, allowlist, ports)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	logger.Info("Discovery complete", "hosts_found", len(hosts))

	if len(hosts) == 0 {
		logger.Warn("No SSH hosts discovered")
		return nil
	}

	// Phase 2: SSH Handshake Analysis
	logger.Info("Starting SSH handshake analysis")
	analyzer := handshake.NewHandshakeAnalyzer(time.Duration(timeout)*time.Second, logger)
	var sshInfos []models.SSHInfo

	for _, host := range hosts {
		sshInfo, err := analyzer.Analyze(ctx, host)
		if err != nil {
			logger.Warn("Handshake analysis failed", "host", host.IP, "port", host.Port, "error", err)
			continue
		}
		sshInfos = append(sshInfos, *sshInfo)
	}

	logger.Info("Handshake analysis complete", "analyzed", len(sshInfos))

	// Phase 3: Security Analysis
	logger.Info("Starting security analysis")
	engine := analyze.NewEngine(baseline, vulnDB, logger)
	var allFindings []models.Finding

	for _, sshInfo := range sshInfos {
		findings := engine.Analyze(&sshInfo)
		allFindings = append(allFindings, findings...)
	}

	logger.Info("Security analysis complete", "total_findings", len(allFindings))

	// Build report
	endTime := time.Now()
	auditReport := buildReport(scanID, startTime, endTime, allowlist, sshInfos, allFindings, version)

	// Generate outputs
	if outputJSON != "" {
		logger.Info("Generating JSON report", "path", outputJSON)
		jsonReporter := report.NewJSONReporter()
		if err := jsonReporter.Generate(&auditReport, outputJSON); err != nil {
			return fmt.Errorf("failed to generate JSON report: %w", err)
		}
	}

	if outputMarkdown != "" {
		logger.Info("Generating Markdown report", "path", outputMarkdown)
		mdReporter := report.NewMarkdownReporter()
		if err := mdReporter.Generate(&auditReport, outputMarkdown); err != nil {
			return fmt.Errorf("failed to generate Markdown report: %w", err)
		}
	}

	if outputSARIF != "" {
		logger.Info("Generating SARIF report", "path", outputSARIF)
		sarifReporter := report.NewSARIFReporter()
		if err := sarifReporter.Generate(&auditReport, outputSARIF); err != nil {
			return fmt.Errorf("failed to generate SARIF report: %w", err)
		}
	}

	if outputHTML != "" {
		logger.Info("Generating HTML dashboard", "path", outputHTML)
		htmlReporter := report.NewHTMLReporter()
		if err := htmlReporter.Generate(&auditReport, outputHTML); err != nil {
			return fmt.Errorf("failed to generate HTML dashboard: %w", err)
		}
	}

	// Print summary to console
	printSummary(auditReport, logger)

	// Check fail-on severity
	if failOnSeverity != "" {
		if shouldFail(auditReport.Summary, strings.ToLower(failOnSeverity)) {
			logger.Error("Scan failed due to severity threshold", "threshold", failOnSeverity)
			os.Exit(1)
		}
	}

	logger.Info("Scan complete", "duration", endTime.Sub(startTime))
	return nil
}

func buildReport(scanID string, startTime, endTime time.Time, targets []string, hosts []models.SSHInfo, findings []models.Finding, toolVersion string) models.Report {
	// Build summary
	summary := models.Summary{
		TotalHosts:         len(hosts),
		TotalFindings:      len(findings),
		FindingsBySeverity: make(map[models.SeverityLevel]int),
		WeakKexUsage:       make(map[string]int),
		WeakCipherUsage:    make(map[string]int),
		WeakMACUsage:       make(map[string]int),
		CVECounts:          make(map[string]int),
	}

	// Aggregate findings by severity
	for _, finding := range findings {
		summary.FindingsBySeverity[finding.Severity]++

		// Count CVEs
		for _, cve := range finding.CVEs {
			summary.CVECounts[cve]++
		}

		// Track weak crypto usage
		if finding.Category == "kex" && (finding.Severity == models.SeverityHigh || finding.Severity == models.SeverityCritical) {
			summary.WeakKexUsage[finding.Title]++
		}
		if finding.Category == "cipher" && (finding.Severity == models.SeverityHigh || finding.Severity == models.SeverityCritical) {
			summary.WeakCipherUsage[finding.Title]++
		}
		if finding.Category == "mac" && (finding.Severity == models.SeverityHigh || finding.Severity == models.SeverityCritical) {
			summary.WeakMACUsage[finding.Title]++
		}
	}

	// Count password auth and root login
	for _, host := range hosts {
		if host.Policy != nil {
			if host.Policy.PasswordAuthentication != nil && *host.Policy.PasswordAuthentication {
				summary.PasswordAuthEnabled++
			}
			if host.Policy.PermitRootLogin == "yes" || host.Policy.PermitRootLogin == "prohibit-password" {
				summary.RootLoginPermitted++
			}
		}
	}

	return models.Report{
		Metadata: models.ReportMetadata{
			ScanID:        scanID,
			StartTime:     startTime,
			EndTime:       endTime,
			Duration:      endTime.Sub(startTime),
			TargetRanges:  targets,
			Authorized:    true,
			ToolVersion:   toolVersion,
			SchemaVersion: "2.0",
		},
		Hosts:       hosts,
		Findings:    findings,
		Summary:     summary,
		GeneratedAt: time.Now(),
	}
}

func printSummary(report models.Report, logger util.Logger) {
	fmt.Println("\n=== SSH Security Audit Summary ===")
	fmt.Printf("Scan ID: %s\n", report.Metadata.ScanID)
	fmt.Printf("Duration: %s\n", report.Metadata.Duration)
	fmt.Printf("Total Hosts: %d\n", report.Summary.TotalHosts)
	fmt.Printf("Total Findings: %d\n\n", report.Summary.TotalFindings)

	fmt.Println("Findings by Severity:")
	for _, severity := range []models.SeverityLevel{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityInfo,
	} {
		count := report.Summary.FindingsBySeverity[severity]
		if count > 0 {
			fmt.Printf("  %s: %d\n", severity, count)
		}
	}

	if report.Summary.PasswordAuthEnabled > 0 {
		fmt.Printf("\n⚠️  Password Auth Enabled: %d hosts (%.1f%%)\n",
			report.Summary.PasswordAuthEnabled,
			float64(report.Summary.PasswordAuthEnabled)/float64(report.Summary.TotalHosts)*100)
	}

	if report.Summary.RootLoginPermitted > 0 {
		fmt.Printf("⚠️  Root Login Permitted: %d hosts (%.1f%%)\n",
			report.Summary.RootLoginPermitted,
			float64(report.Summary.RootLoginPermitted)/float64(report.Summary.TotalHosts)*100)
	}

	if len(report.Summary.CVECounts) > 0 {
		fmt.Printf("\n🔍 CVEs Found: %d unique\n", len(report.Summary.CVECounts))
	}

	fmt.Println()
}

func shouldFail(summary models.Summary, threshold string) bool {
	severityOrder := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}

	thresholdLevel, ok := severityOrder[threshold]
	if !ok {
		return false
	}

	// Check if any findings meet or exceed the threshold
	if thresholdLevel >= severityOrder["critical"] && summary.FindingsBySeverity[models.SeverityCritical] > 0 {
		return true
	}
	if thresholdLevel >= severityOrder["high"] && summary.FindingsBySeverity[models.SeverityHigh] > 0 {
		return true
	}
	if thresholdLevel >= severityOrder["medium"] && summary.FindingsBySeverity[models.SeverityMedium] > 0 {
		return true
	}
	if thresholdLevel >= severityOrder["low"] && summary.FindingsBySeverity[models.SeverityLow] > 0 {
		return true
	}

	return false
}

func getDefaultBaseline() *storage.Baseline {
	baseline := &storage.Baseline{}
	
	// Default allowed algorithms (modern, secure)
	baseline.KexAlgorithms.Allowed = []string{
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"diffie-hellman-group-exchange-sha256",
	}
	
	baseline.KexAlgorithms.Deprecated = []string{
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group-exchange-sha1",
	}
	
	baseline.KexAlgorithms.Forbidden = []string{
		"diffie-hellman-group1-sha1",
	}
	
	baseline.Ciphers.Allowed = []string{
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-gcm@openssh.com",
		"aes256-ctr",
		"aes192-ctr",
		"aes128-ctr",
	}
	
	baseline.Ciphers.Forbidden = []string{
		"3des-cbc",
		"aes128-cbc",
		"aes192-cbc",
		"aes256-cbc",
		"arcfour",
		"arcfour256",
		"arcfour128",
	}
	
	baseline.MACs.Allowed = []string{
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
	}
	
	baseline.MACs.Forbidden = []string{
		"hmac-md5",
		"hmac-md5-96",
		"hmac-sha1-96",
	}
	
	baseline.Policies.PasswordAuthentication = false
	baseline.Policies.PermitRootLogin = "no"
	baseline.Policies.MaxAuthTries = 3
	baseline.Policies.PermitEmptyPasswords = false
	
	return baseline
}

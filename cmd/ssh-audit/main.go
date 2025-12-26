package main

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"os"
	"strings"
	"time"

	import_targets "github.com/amariwan/ssh-hack/internal/net/import"
	clouddiscover "github.com/amariwan/ssh-hack/internal/net/discover"

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
	allowlist      []string
	ports          []int
	concurrency    int
	timeout        int
	rateLimit      int
	dnsReverse     bool
	dryRun         bool
	authorized     bool
	baselineFile   string
	vulnsFile      string
	outputJSON     string
	outputMarkdown string
	outputHTML     string
	outputSARIF    string
	failOnSeverity string
	logLevel       string
	logFile        string
)

func main() {
	// Use shared rootCmd from root.go to unify flags and execution
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Initialize logger (already set up in persistentPreRunE, but obtain instance)
	logger, err := util.InitLogger(logLevel, logFile)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	// If scheduling is requested, start scheduler (requires sched tag)
	if schedule != "" {
		cfg := SchedulerConfig{
			CronExpr:       schedule,
			SlackWebhook:   alertSlackWebhook,
			AlertThreshold: alertThreshold,
			StoragePath:    "ssh-audit.db",
		}
		s, err := NewScheduler(cfg, logger)
		if err != nil {
			return err
		}
		ctx := context.Background()
		return s.Start(ctx)
	}

	// Regular one-off audit
	ctx := context.Background()
	auditReport, err := runAudit(ctx)
	if err != nil {
		return err
	}

	// Generate outputs
	if outputJSON != "" {
		logger.Info("Generating JSON report", "path", outputJSON)
		if err := report.NewJSONReporter().Generate(auditReport, outputJSON); err != nil {
			return fmt.Errorf("failed to generate JSON report: %w", err)
		}
	}
	if outputMarkdown != "" {
		logger.Info("Generating Markdown report", "path", outputMarkdown)
		if err := report.NewMarkdownReporter().Generate(auditReport, outputMarkdown); err != nil {
			return fmt.Errorf("failed to generate Markdown report: %w", err)
		}
	}
	if outputSARIF != "" {
		logger.Info("Generating SARIF report", "path", outputSARIF)
		if err := report.NewSARIFReporter().Generate(auditReport, outputSARIF); err != nil {
			return fmt.Errorf("failed to generate SARIF report: %w", err)
		}
	}
	if outputHTML != "" {
		logger.Info("Generating HTML dashboard", "path", outputHTML)
		if err := report.NewHTMLReporter().Generate(auditReport, outputHTML); err != nil {
			return fmt.Errorf("failed to generate HTML dashboard: %w", err)
		}
		if serve {
			// Serve the generated HTML on localhost:8080
			abs := outputHTML
			if !filepath.IsAbs(abs) {
				abs, _ = filepath.Abs(outputHTML)
			}
			logger.Info("Serving HTML dashboard", "url", "http://localhost:8080", "file", abs)
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, abs)
			})
			if err := http.ListenAndServe(":8080", nil); err != nil {
				return fmt.Errorf("failed to serve HTML: %w", err)
			}
		}
	}

	// If this was a dry-run, do not print summary or write outputs
	if dryRun {
		logger.Info("Dry run completed")
		return nil
	}

	// Print summary to console
	printSummary(*auditReport, logger)

	// Check fail-on severity
	if failOnSeverity != "" {
		if shouldFail(auditReport.Summary, strings.ToLower(failOnSeverity)) {
			logger.Error("Scan failed due to severity threshold", "threshold", failOnSeverity)
			os.Exit(1)
		}
	}
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

// runAudit executes the full audit pipeline and returns the generated report
func runAudit(ctx context.Context) (*models.Report, error) {
	logger, err := util.InitLogger(logLevel, logFile)
	if err != nil {
		return nil, fmt.Errorf("logger init failed: %w", err)
	}

	// Dry run: just print targets after aggregation
	targets, portsUnion, importSource, err := aggregateTargets(logger)
	if err != nil {
		return nil, err
	}
	if dryRun {
		logger.Info("Dry run mode: listing targets without scanning")
		for _, target := range targets {
			for _, port := range portsUnion {
				logger.Info("Target", "address", fmt.Sprintf("%s:%d", target, port))
			}
		}
		return &models.Report{ // Minimal stub report
			Metadata: models.ReportMetadata{
				ScanID:        uuid.New().String(),
				StartTime:     time.Now(),
				EndTime:       time.Now(),
				Duration:      0,
				TargetRanges:  targets,
				Authorized:    authorized,
				ToolVersion:   version,
				SchemaVersion: "2.0",
				ImportSource:  importSource,
			},
			Hosts:       []models.SSHInfo{},
			Findings:    []models.Finding{},
			Summary:     models.Summary{FindingsBySeverity: map[models.SeverityLevel]int{}},
			GeneratedAt: time.Now(),
		}, nil
	}

	// Load baseline and vuln DB
	baseline, err := storage.LoadBaseline(baselineFile)
	if err != nil {
		logger.Warn("Failed to load baseline, using defaults", "error", err)
		baseline = getDefaultBaseline()
	}
	vulnDB, err := storage.LoadVulnDatabase(vulnsFile)
	if err != nil {
		logger.Warn("Failed to load vulnerability database, using empty DB", "error", err)
		vulnDB = &storage.VulnDatabase{}
	}

	scanID := uuid.New().String()
	startTime := time.Now()

	logger.Info("Starting scan", "scan_id", scanID, "targets", targets, "ports", portsUnion)
	scanner := scan.NewTCPScanner(concurrency, time.Duration(timeout)*time.Second, rateLimit, dnsReverse, logger)
	hosts, err := scanner.Scan(ctx, targets, portsUnion)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	logger.Info("Discovery complete", "hosts_found", len(hosts))
	if len(hosts) == 0 {
		endTime := time.Now()
		rpt := buildReport(scanID, startTime, endTime, targets, []models.SSHInfo{}, []models.Finding{}, version)
		rpt.Metadata.ImportSource = importSource
		return &rpt, nil
	}

	// Handshake analysis + fingerprinting
	analyzer := handshake.NewHandshakeAnalyzer(time.Duration(timeout)*time.Second, logger)
	fingerprinter := handshake.NewFingerprinter()
	var sshInfos []models.SSHInfo
	for _, host := range hosts {
		sshInfo, err := analyzer.Analyze(ctx, host)
		if err != nil {
			logger.Warn("Handshake analysis failed", "host", host.IP, "port", host.Port, "error", err)
			continue
		}
		impl, conf := fingerprinter.Identify(host.Banner, sshInfo.KexAlgorithms)
		sshInfo.ImplementationType = impl
		sshInfo.ImplementationConf = conf * 100.0
		sshInfos = append(sshInfos, *sshInfo)
	}
	logger.Info("Handshake analysis complete", "analyzed", len(sshInfos))

	// Security analysis + remediation scripts
	engine := analyze.NewEngine(baseline, vulnDB, logger)
	var allFindings []models.Finding
	for _, si := range sshInfos {
		fs := engine.Analyze(&si)
		allFindings = append(allFindings, fs...)
	}

	// Anomaly detection
	anomalies := analyze.NewAnomalyDetector(0).Detect(sshInfos)
	allFindings = append(allFindings, anomalies...)

	endTime := time.Now()
	auditReport := buildReport(scanID, startTime, endTime, targets, sshInfos, allFindings, version)
	auditReport.Metadata.ImportSource = importSource
	return &auditReport, nil
}

// aggregateTargets merges CLI allowlist with imports and cloud discovery
func aggregateTargets(logger util.Logger) ([]string, []int, string, error) {
	targets := make([]string, 0)
	portsSet := make(map[int]struct{})
	importSources := make([]string, 0)

	// Start with CLI allowlist and ports
	// append allowlist (may be empty)
	targets = append(targets, allowlist...)
	for _, p := range ports {
		portsSet[p] = struct{}{}
	}

	// Shodan import
	if importShodan != "" {
		shodanTargets, err := import_targets.ImportShodanJSON(importShodan)
		if err != nil {
			return nil, nil, "", fmt.Errorf("shodan import failed: %w", err)
		}
		for _, t := range shodanTargets {
			if t.IP != nil {
				targets = append(targets, t.IP.String())
			}
			if t.Port > 0 {
				portsSet[t.Port] = struct{}{}
			}
		}
		importSources = append(importSources, "shodan")
	}

	// Nmap import
	if importNmap != "" {
		nmapTargets, err := import_targets.ImportNmapXML(importNmap)
		if err != nil {
			logger.Warn("Nmap import not available or failed", "error", err)
		} else {
			for _, t := range nmapTargets {
				if t.IP != nil {
					targets = append(targets, t.IP.String())
				}
				if t.Port > 0 {
					portsSet[t.Port] = struct{}{}
				}
			}
			importSources = append(importSources, "nmap")
		}
	}

	// AWS discovery
	if strings.ToLower(cloudProvider) == "aws" {
		cfg := clouddiscover.AWSDiscoveryConfig{
			Region:       awsRegion,
			UsePublicIP:  awsPublicIP,
			UsePrivateIP: awsPrivateIP,
		}
		disc, err := clouddiscover.NewAWSDiscoverer(cfg)
		if err != nil {
			logger.Warn("AWS discovery not available or failed", "error", err)
		} else {
			ctx := context.Background()
			awsTargets, err := disc.Discover(ctx)
			if err != nil {
				logger.Warn("AWS discovery failed", "error", err)
			} else {
				for _, t := range awsTargets {
					if t.IP != nil {
						targets = append(targets, t.IP.String())
					}
					if t.Port > 0 {
						portsSet[t.Port] = struct{}{}
					}
				}
				importSources = append(importSources, "aws")
			}
		}
	}

	// Deduplicate targets
	dedup := make(map[string]struct{})
	uniqTargets := make([]string, 0)
	for _, t := range targets {
		if _, ok := dedup[t]; !ok {
			dedup[t] = struct{}{}
			uniqTargets = append(uniqTargets, t)
		}
	}

	// Ports union
	portsUnion := make([]int, 0, len(portsSet))
	for p := range portsSet {
		portsUnion = append(portsUnion, p)
	}

	source := "cli"
	if len(importSources) > 0 {
		source = source + "+" + strings.Join(importSources, "+")
	}
	return uniqTargets, portsUnion, source, nil
}

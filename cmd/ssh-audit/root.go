package main

import (
	"fmt"
	"github.com/amariwan/ssh-hack/internal/util"
	"github.com/spf13/cobra"
)

// usageError signals usage/consent related error which maps to exit code 64
type usageError struct {
	msg string
}

func (u *usageError) Error() string { return u.msg }

// rootCmd and flags live here. runAudit (in main.go) is used as RunE.
var rootCmd *cobra.Command

func init() {
	rootCmd = &cobra.Command{
		Use:   "ssh-audit",
		Short: "Enterprise SSH Inventory & Hardening Auditor",
		Long: `A security tool for SSH infrastructure auditing.
Discovers SSH hosts, analyzes cryptographic parameters, evaluates policies,
and generates comprehensive security reports.`,
		PersistentPreRunE: persistentPreRunE,
		RunE:              run,
	}

	// Discovery flags
	rootCmd.Flags().StringSliceVar(&allowlist, "allowlist", []string{}, "Allowed CIDR ranges (required, comma-separated)")
	rootCmd.Flags().IntSliceVar(&ports, "ports", []int{22}, "SSH ports to scan (comma-separated)")
	rootCmd.Flags().IntVar(&concurrency, "concurrency", 50, "Concurrent scan workers")
	rootCmd.Flags().IntVar(&timeout, "timeout", 5, "Connection timeout (seconds)")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 100, "Max requests per second")
	rootCmd.Flags().BoolVar(&dnsReverse, "dns-reverse", false, "Perform reverse DNS lookup")

	// Security flags
	rootCmd.Flags().BoolVar(&authorized, "i-am-authorized", false, "Consent flag (REQUIRED)")
	rootCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Dry run (parse config only)")

	// Analysis flags
	rootCmd.Flags().StringVar(&baselineFile, "baseline", "configs/baseline.yml", "Security baseline file")
	rootCmd.Flags().StringVar(&vulnsFile, "vulns", "configs/vulns.yml", "Vulnerability database file")

	// Output flags
	rootCmd.Flags().StringVar(&outputJSON, "output-json", "report.json", "JSON report output path")
	rootCmd.Flags().StringVar(&outputMarkdown, "output-markdown", "report.md", "Markdown report output path")
	rootCmd.Flags().StringVar(&outputSARIF, "output-sarif", "", "SARIF report output path (optional)")
	rootCmd.Flags().StringVar(&outputHTML, "output-html", "", "HTML dashboard output path (optional)")
	rootCmd.Flags().BoolVar(&serve, "serve", false, "Serve HTML report on localhost:8080 (requires --output-html)")
	rootCmd.Flags().StringVar(&failOnSeverity, "fail-on", "", "Fail CI if findings >= severity (critical|high|medium|low)")

	// Import flags (v2)
	rootCmd.Flags().StringVar(&importShodan, "import-shodan", "", "Import targets from Shodan JSON file")
	rootCmd.Flags().StringVar(&importNmap, "import-nmap-xml", "", "Import targets from Nmap XML file (requires 'nmap' build tag)")

	// Scheduling flags (v2, requires 'sched' build tag)
	rootCmd.Flags().StringVar(&schedule, "schedule", "", "Cron expression for periodic scans (e.g., '0 3 * * *')")
	rootCmd.Flags().StringVar(&alertSlackWebhook, "alert-slack-webhook", "", "Slack webhook URL for alerts")
	rootCmd.Flags().Float64Var(&alertThreshold, "alert-threshold", 10.0, "Alert if score drops by this % (default: 10)")

	// Cloud discovery flags (v2, requires 'cloud' build tag)
	rootCmd.Flags().StringVar(&cloudProvider, "provider", "", "Cloud provider (aws)")
	rootCmd.Flags().StringVar(&awsRegion, "aws-region", "us-east-1", "AWS region for EC2 discovery")
	rootCmd.Flags().BoolVar(&awsPublicIP, "aws-public-ip", true, "Include EC2 public IPs")
	rootCmd.Flags().BoolVar(&awsPrivateIP, "aws-private-ip", false, "Include EC2 private IPs")

	// Logging
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug|info|warn|error)")
	rootCmd.Flags().StringVar(&logFile, "log-file", "", "Optional log file path (also mirrored to stderr)")

	if err := rootCmd.MarkFlagRequired("allowlist"); err != nil {
		// Initialization failure is a programming error; panic to fail fast in tests/builds
		panic(err)
	}
}

// persistentPreRunE initializes logger and performs consent check
func persistentPreRunE(cmd *cobra.Command, args []string) error {
	// init logger (writes to stderr by default)
	_, err := util.InitLogger(logLevel, logFile)
	if err != nil {
		// return as generic error (mapped to exit code 1)
		return fmt.Errorf("logger init failed: %w", err)
	}

	if !authorized {
		return &usageError{msg: "consent required: pass --i-am-authorized"}
	}
	return nil
}

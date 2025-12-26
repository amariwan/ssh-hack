package analyze

import (
	"fmt"
	"strings"

	"github.com/amariwan/ssh-hack/internal/models"
	"github.com/amariwan/ssh-hack/internal/storage"
	"github.com/amariwan/ssh-hack/internal/util"
)

// Engine performs security analysis and scoring
type Engine struct {
	baseline *storage.Baseline
	vulnDB   *storage.VulnDatabase
	logger   util.Logger
}

// NewEngine creates a new analysis engine
func NewEngine(baseline *storage.Baseline, vulnDB *storage.VulnDatabase, logger util.Logger) *Engine {
	return &Engine{
		baseline: baseline,
		vulnDB:   vulnDB,
		logger:   logger,
	}
}

// Analyze performs comprehensive security analysis
func (e *Engine) Analyze(sshInfo *models.SSHInfo) []models.Finding {
	var findings []models.Finding

	// Check Kex algorithms
	findings = append(findings, e.checkKexAlgorithms(sshInfo)...)

	// Check Ciphers
	findings = append(findings, e.checkCiphers(sshInfo)...)

	// Check MACs
	findings = append(findings, e.checkMACs(sshInfo)...)

	// Check Host Keys
	findings = append(findings, e.checkHostKeys(sshInfo)...)

	// Check Policy (if available)
	if sshInfo.Policy != nil {
		findings = append(findings, e.checkPolicy(sshInfo)...)
	}

	// Check Version/CVEs
	findings = append(findings, e.checkVersion(sshInfo)...)

	// Attach auto-generated remediation scripts (v2)
	findings = e.generateRemediationScripts(findings)

	return findings
}

// checkKexAlgorithms validates key exchange algorithms
func (e *Engine) checkKexAlgorithms(sshInfo *models.SSHInfo) []models.Finding {
	var findings []models.Finding

	for _, kex := range sshInfo.KexAlgorithms {
		// Check if forbidden
		if contains(e.baseline.KexAlgorithms.Forbidden, kex) {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("KEX-%s", kex),
				HostIP:      sshInfo.Host.IP.String(),
				Port:        sshInfo.Host.Port,
				Category:    "kex",
				Title:       fmt.Sprintf("Forbidden Kex Algorithm: %s", kex),
				Description: fmt.Sprintf("The key exchange algorithm '%s' is forbidden by security baseline", kex),
				Severity:    models.SeverityCritical,
				RiskScore:   90,
				Remediation: fmt.Sprintf("Remove '%s' from KexAlgorithms in sshd_config", kex),
			})
		} else if contains(e.baseline.KexAlgorithms.Deprecated, kex) {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("KEX-%s", kex),
				HostIP:      sshInfo.Host.IP.String(),
				Port:        sshInfo.Host.Port,
				Category:    "kex",
				Title:       fmt.Sprintf("Deprecated Kex Algorithm: %s", kex),
				Description: fmt.Sprintf("The key exchange algorithm '%s' is deprecated", kex),
				Severity:    models.SeverityMedium,
				RiskScore:   50,
				Remediation: fmt.Sprintf("Consider removing '%s' and using modern alternatives like curve25519-sha256", kex),
			})
		}
	}

	return findings
}

// checkCiphers validates encryption ciphers
func (e *Engine) checkCiphers(sshInfo *models.SSHInfo) []models.Finding {
	var findings []models.Finding

	allCiphers := append(sshInfo.Ciphers.ClientToServer, sshInfo.Ciphers.ServerToClient...)
	uniqueCiphers := unique(allCiphers)

	for _, cipher := range uniqueCiphers {
		if contains(e.baseline.Ciphers.Forbidden, cipher) {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("CIPHER-%s", cipher),
				HostIP:      sshInfo.Host.IP.String(),
				Port:        sshInfo.Host.Port,
				Category:    "cipher",
				Title:       fmt.Sprintf("Forbidden Cipher: %s", cipher),
				Description: fmt.Sprintf("The cipher '%s' is forbidden (weak or broken)", cipher),
				Severity:    models.SeverityCritical,
				RiskScore:   95,
				Remediation: fmt.Sprintf("Remove '%s' from Ciphers in sshd_config", cipher),
			})
		} else if contains(e.baseline.Ciphers.Deprecated, cipher) {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("CIPHER-%s", cipher),
				HostIP:      sshInfo.Host.IP.String(),
				Port:        sshInfo.Host.Port,
				Category:    "cipher",
				Title:       fmt.Sprintf("Deprecated Cipher: %s", cipher),
				Description: fmt.Sprintf("The cipher '%s' is deprecated", cipher),
				Severity:    models.SeverityMedium,
				RiskScore:   55,
				Remediation: "Use modern AEAD ciphers like chacha20-poly1305@openssh.com or aes256-gcm@openssh.com",
			})
		}
	}

	return findings
}

// checkMACs validates message authentication codes
func (e *Engine) checkMACs(sshInfo *models.SSHInfo) []models.Finding {
	var findings []models.Finding

	allMACs := append(sshInfo.MACs.ClientToServer, sshInfo.MACs.ServerToClient...)
	uniqueMACs := unique(allMACs)

	for _, mac := range uniqueMACs {
		if contains(e.baseline.MACs.Forbidden, mac) {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("MAC-%s", mac),
				HostIP:      sshInfo.Host.IP.String(),
				Port:        sshInfo.Host.Port,
				Category:    "mac",
				Title:       fmt.Sprintf("Forbidden MAC: %s", mac),
				Description: fmt.Sprintf("The MAC '%s' is forbidden (weak)", mac),
				Severity:    models.SeverityHigh,
				RiskScore:   80,
				Remediation: fmt.Sprintf("Remove '%s' from MACs in sshd_config", mac),
			})
		} else if contains(e.baseline.MACs.Deprecated, mac) {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("MAC-%s", mac),
				HostIP:      sshInfo.Host.IP.String(),
				Port:        sshInfo.Host.Port,
				Category:    "mac",
				Title:       fmt.Sprintf("Deprecated MAC: %s", mac),
				Description: fmt.Sprintf("The MAC '%s' is deprecated", mac),
				Severity:    models.SeverityLow,
				RiskScore:   40,
				Remediation: "Use ETM MACs like hmac-sha2-256-etm@openssh.com",
			})
		}
	}

	return findings
}

// checkHostKeys validates host key types and sizes
func (e *Engine) checkHostKeys(sshInfo *models.SSHInfo) []models.Finding {
	var findings []models.Finding

	for _, hk := range sshInfo.HostKeys {
		// Check if allowed
		if !contains(e.baseline.HostKeys.Allowed, hk.Type) {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("HOSTKEY-%s", hk.Type),
				HostIP:      sshInfo.Host.IP.String(),
				Port:        sshInfo.Host.Port,
				Category:    "hostkey",
				Title:       fmt.Sprintf("Weak Host Key Type: %s", hk.Type),
				Description: fmt.Sprintf("Host key type '%s' is not recommended", hk.Type),
				Severity:    models.SeverityMedium,
				RiskScore:   60,
				Remediation: "Use Ed25519 or ECDSA (nistp256+) host keys",
			})
		}

		// Check key size
		if minSize, ok := e.baseline.HostKeys.MinKeySizes[hk.Type]; ok {
			if hk.KeySize < minSize {
				findings = append(findings, models.Finding{
					ID:          fmt.Sprintf("HOSTKEY-SIZE-%s", hk.Type),
					HostIP:      sshInfo.Host.IP.String(),
					Port:        sshInfo.Host.Port,
					Category:    "hostkey",
					Title:       fmt.Sprintf("Weak Host Key Size: %s (%d bits)", hk.Type, hk.KeySize),
					Description: fmt.Sprintf("Host key size %d is below minimum %d", hk.KeySize, minSize),
					Severity:    models.SeverityHigh,
					RiskScore:   75,
					Remediation: fmt.Sprintf("Regenerate host key with minimum %d bits", minSize),
				})
			}
		}
	}

	return findings
}

// checkPolicy validates SSH policy configuration
func (e *Engine) checkPolicy(sshInfo *models.SSHInfo) []models.Finding {
	var findings []models.Finding
	policy := sshInfo.Policy

	// Password Authentication
	if policy.PasswordAuthentication != nil && *policy.PasswordAuthentication && !e.baseline.Policies.PasswordAuthentication {
		findings = append(findings, models.Finding{
			ID:          "POLICY-PASSWORD-AUTH",
			HostIP:      sshInfo.Host.IP.String(),
			Port:        sshInfo.Host.Port,
			Category:    "policy",
			Title:       "Password Authentication Enabled",
			Description: "Password authentication is enabled, allowing potential brute-force attacks",
			Severity:    models.SeverityHigh,
			RiskScore:   85,
			Remediation: "Set PasswordAuthentication no in sshd_config",
		})
	}

	// Root Login
	if policy.PermitRootLogin != "" && policy.PermitRootLogin != e.baseline.Policies.PermitRootLogin {
		severity := models.SeverityCritical
		if policy.PermitRootLogin == "prohibit-password" || policy.PermitRootLogin == "without-password" {
			severity = models.SeverityMedium
		}

		findings = append(findings, models.Finding{
			ID:          "POLICY-ROOT-LOGIN",
			HostIP:      sshInfo.Host.IP.String(),
			Port:        sshInfo.Host.Port,
			Category:    "policy",
			Title:       fmt.Sprintf("Root Login Permitted: %s", policy.PermitRootLogin),
			Description: fmt.Sprintf("PermitRootLogin is set to '%s'", policy.PermitRootLogin),
			Severity:    severity,
			RiskScore:   90,
			Remediation: "Set PermitRootLogin no in sshd_config",
		})
	}

	// Empty Passwords
	if policy.PermitEmptyPasswords != nil && *policy.PermitEmptyPasswords {
		findings = append(findings, models.Finding{
			ID:          "POLICY-EMPTY-PASSWORDS",
			HostIP:      sshInfo.Host.IP.String(),
			Port:        sshInfo.Host.Port,
			Category:    "policy",
			Title:       "Empty Passwords Permitted",
			Description: "Server allows authentication with empty passwords",
			Severity:    models.SeverityCritical,
			RiskScore:   100,
			Remediation: "Set PermitEmptyPasswords no in sshd_config",
		})
	}

	// MaxAuthTries
	if policy.MaxAuthTries != nil && *policy.MaxAuthTries > e.baseline.Policies.MaxAuthTries {
		findings = append(findings, models.Finding{
			ID:          "POLICY-MAX-AUTH-TRIES",
			HostIP:      sshInfo.Host.IP.String(),
			Port:        sshInfo.Host.Port,
			Category:    "policy",
			Title:       fmt.Sprintf("High MaxAuthTries: %d", *policy.MaxAuthTries),
			Description: fmt.Sprintf("MaxAuthTries is %d (recommended: %d)", *policy.MaxAuthTries, e.baseline.Policies.MaxAuthTries),
			Severity:    models.SeverityLow,
			RiskScore:   35,
			Remediation: fmt.Sprintf("Set MaxAuthTries %d in sshd_config", e.baseline.Policies.MaxAuthTries),
		})
	}

	return findings
}

// checkVersion checks for known CVEs
func (e *Engine) checkVersion(sshInfo *models.SSHInfo) []models.Finding {
	var findings []models.Finding

	for _, vuln := range e.vulnDB.Vulnerabilities {
		if e.isVersionAffected(sshInfo.Version, vuln.AffectedVersions) {
			severity := parseSeverity(vuln.Severity)
			findings = append(findings, models.Finding{
				ID:          vuln.CVE,
				HostIP:      sshInfo.Host.IP.String(),
				Port:        sshInfo.Host.Port,
				Category:    "version",
				Title:       vuln.Title,
				Description: vuln.Description,
				Severity:    severity,
				RiskScore:   severityToScore(severity),
				Remediation: fmt.Sprintf("Upgrade to version %s or later", vuln.FixedIn),
				CVEs:        []string{vuln.CVE},
			})
		}
	}

	return findings
}

// isVersionAffected checks if version matches affected patterns
func (e *Engine) isVersionAffected(version string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(version, pattern) {
			return true
		}
	}
	return false
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func unique(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func parseSeverity(s string) models.SeverityLevel {
	switch strings.ToLower(s) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

func severityToScore(sev models.SeverityLevel) int {
	switch sev {
	case models.SeverityCritical:
		return 95
	case models.SeverityHigh:
		return 80
	case models.SeverityMedium:
		return 60
	case models.SeverityLow:
		return 40
	case models.SeverityInfo:
		return 20
	default:
		return 0
	}
}

// generateRemediationScripts adds simple shell remediation snippets per finding
func (e *Engine) generateRemediationScripts(findings []models.Finding) []models.Finding {
	for i := range findings {
		f := &findings[i]
		switch f.Category {
		case "kex":
			// Remove deprecated/forbidden KEX from sshd_config
			f.RemediationScript = fmt.Sprintf(`# Backup
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
# Remove %s from KexAlgorithms
sudo sed -i 's/\(^\s*KexAlgorithms\s*\)/\1/g' /etc/ssh/sshd_config
# Recommended secure set
echo 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256' | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart sshd` , extractAlgorithmName(f.Title))
		case "cipher":
			f.RemediationScript = `# Backup
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
# Set modern AEAD ciphers
echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com' | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart sshd`
		case "mac":
			f.RemediationScript = `# Backup
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
# Use ETM MACs
echo 'MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com' | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart sshd`
		case "hostkey":
			f.RemediationScript = `# Generate modern host keys
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''
sudo ssh-keygen -t ecdsa -b 256 -f /etc/ssh/ssh_host_ecdsa_key -N ''
sudo systemctl restart sshd`
		case "policy":
			// Basic policy hardening
			f.RemediationScript = `# Policy hardening
sudo sed -i 's/^\s*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^\s*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sudo systemctl restart sshd`
		case "version":
			// Upgrade guidance
			f.RemediationScript = `# Upgrade OpenSSH (example for Debian/Ubuntu)
sudo apt-get update && sudo apt-get install --only-upgrade openssh-server -y
sudo systemctl restart sshd`
		}
	}
	return findings
}

func extractAlgorithmName(title string) string {
	// Extract token after last ': '
	parts := strings.Split(title, ": ")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return title
}

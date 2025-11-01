package report

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/amariwan/ssh-hack/internal/models"
)

// RemediationGenerator generates actionable fix scripts
type RemediationGenerator struct {
	templates map[string]*template.Template
}

// NewRemediationGenerator creates a new generator
func NewRemediationGenerator() *RemediationGenerator {
	gen := &RemediationGenerator{
		templates: make(map[string]*template.Template),
	}
	gen.initTemplates()
	return gen
}

// Generate creates remediation script for a finding
func (g *RemediationGenerator) Generate(finding *models.Finding) string {
	tmplKey := g.getTemplateKey(finding)
	tmpl, exists := g.templates[tmplKey]
	if !exists {
		return "" // No specific template
	}

	var buf bytes.Buffer
	data := g.prepareTemplateData(finding)
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Sprintf("# Template error: %v\n", err)
	}

	return buf.String()
}

// getTemplateKey maps finding category/title to template
func (g *RemediationGenerator) getTemplateKey(finding *models.Finding) string {
	category := finding.Category
	title := strings.ToLower(finding.Title)

	if category == "cipher" && strings.Contains(title, "weak") {
		return "weak-cipher"
	}
	if category == "kex" && strings.Contains(title, "forbidden") {
		return "weak-kex"
	}
	if category == "mac" && strings.Contains(title, "weak") {
		return "weak-mac"
	}
	if category == "policy" && strings.Contains(title, "root") {
		return "permit-root-login"
	}
	if category == "policy" && strings.Contains(title, "password") {
		return "password-auth"
	}
	return ""
}

// prepareTemplateData extracts data for template
func (g *RemediationGenerator) prepareTemplateData(finding *models.Finding) map[string]interface{} {
	data := map[string]interface{}{
		"HostIP":      finding.HostIP,
		"Port":        finding.Port,
		"Title":       finding.Title,
		"Description": finding.Description,
		"Severity":    finding.Severity,
	}

	// Extract algorithm name from title (e.g., "Weak Cipher: aes128-cbc" -> "aes128-cbc")
	if strings.Contains(finding.Title, ":") {
		parts := strings.SplitN(finding.Title, ":", 2)
		if len(parts) == 2 {
			data["Algorithm"] = strings.TrimSpace(parts[1])
		}
	}

	return data
}

// initTemplates initializes all remediation templates
func (g *RemediationGenerator) initTemplates() {
	g.templates["weak-cipher"] = template.Must(template.New("weak-cipher").Parse(weakCipherTemplate))
	g.templates["weak-kex"] = template.Must(template.New("weak-kex").Parse(weakKexTemplate))
	g.templates["weak-mac"] = template.Must(template.New("weak-mac").Parse(weakMACTemplate))
	g.templates["permit-root-login"] = template.Must(template.New("permit-root-login").Parse(permitRootLoginTemplate))
	g.templates["password-auth"] = template.Must(template.New("password-auth").Parse(passwordAuthTemplate))
}

// Template definitions (idempotent shell snippets)

const weakCipherTemplate = `# Remediation: Remove weak cipher {{ .Algorithm }}
# Host: {{ .HostIP }}:{{ .Port }}
# Severity: {{ .Severity }}

# 1. Backup current config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)

# 2. Remove weak cipher from sshd_config (idempotent)
# Recommended strong ciphers (OpenSSH 7.4+):
STRONG_CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"

sudo sed -i.tmp '/^Ciphers/d' /etc/ssh/sshd_config
echo "Ciphers $STRONG_CIPHERS" | sudo tee -a /etc/ssh/sshd_config

# 3. Test config
sudo sshd -t

# 4. Restart SSH (preserve connections)
sudo systemctl reload sshd || sudo service ssh reload

# 5. Verify
ssh -Q cipher | grep -E "(chacha20|aes.*gcm|aes.*ctr)"
`

const weakKexTemplate = `# Remediation: Remove weak KEX algorithm {{ .Algorithm }}
# Host: {{ .HostIP }}:{{ .Port }}
# Severity: {{ .Severity }}

# 1. Backup
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)

# 2. Set strong KEX algorithms
STRONG_KEX="curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"

sudo sed -i.tmp '/^KexAlgorithms/d' /etc/ssh/sshd_config
echo "KexAlgorithms $STRONG_KEX" | sudo tee -a /etc/ssh/sshd_config

# 3. Test & reload
sudo sshd -t && sudo systemctl reload sshd

# 4. Verify
ssh -Q kex | grep -E "(curve25519|diffie-hellman-group1[68])"
`

const weakMACTemplate = `# Remediation: Remove weak MAC {{ .Algorithm }}
# Host: {{ .HostIP }}:{{ .Port }}
# Severity: {{ .Severity }}

# 1. Backup
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)

# 2. Set strong MACs (ETM = Encrypt-Then-MAC)
STRONG_MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"

sudo sed -i.tmp '/^MACs/d' /etc/ssh/sshd_config
echo "MACs $STRONG_MACS" | sudo tee -a /etc/ssh/sshd_config

# 3. Test & reload
sudo sshd -t && sudo systemctl reload sshd
`

const permitRootLoginTemplate = `# Remediation: Disable root login
# Host: {{ .HostIP }}:{{ .Port }}
# Severity: {{ .Severity }}

# 1. Backup
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)

# 2. Disable PermitRootLogin (idempotent)
sudo sed -i.tmp 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
# Add if not exists
grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config

# 3. Test & reload
sudo sshd -t && sudo systemctl reload sshd

# 4. Verify
sudo sshd -T | grep -i permitrootlogin
# Expected: permitrootlogin no
`

const passwordAuthTemplate = `# Remediation: Disable password authentication
# Host: {{ .HostIP }}:{{ .Port }}
# Severity: {{ .Severity }}

# CAUTION: Ensure SSH key-based auth is configured BEFORE applying!
# Test: ssh -i ~/.ssh/id_rsa user@{{ .HostIP }}

# 1. Backup
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)

# 2. Disable password auth
sudo sed -i.tmp 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config

# Also disable challenge-response
sudo sed -i.tmp 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
grep -q '^ChallengeResponseAuthentication' /etc/ssh/sshd_config || echo 'ChallengeResponseAuthentication no' | sudo tee -a /etc/ssh/sshd_config

# 3. Test & reload
sudo sshd -t && sudo systemctl reload sshd

# 4. Verify
sudo sshd -T | grep -E '(passwordauthentication|challengeresponseauthentication)'
# Expected: both 'no'
`

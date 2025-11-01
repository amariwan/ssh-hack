package report

import (
	"strings"
	"testing"
	"time"

	"github.com/amariwan/ssh-hack/internal/models"
)

func TestRemediationGenerator(t *testing.T) {
	gen := NewRemediationGenerator()

	tests := []struct {
		name     string
		finding  models.Finding
		wantContains []string
	}{
		{
			name: "weak cipher",
			finding: models.Finding{
				HostIP:   "10.0.0.1",
				Port:     22,
				Category: "cipher",
				Title:    "Weak Cipher: aes128-cbc",
				Severity: models.SeverityHigh,
			},
			wantContains: []string{
				"Remediation",
				"aes128-cbc",
				"Ciphers",
				"chacha20-poly1305",
				"sshd_config",
			},
		},
		{
			name: "forbidden kex",
			finding: models.Finding{
				HostIP:   "10.0.0.2",
				Port:     22,
				Category: "kex",
				Title:    "Forbidden Kex Algorithm: diffie-hellman-group1-sha1",
				Severity: models.SeverityCritical,
			},
			wantContains: []string{
				"KexAlgorithms",
				"curve25519",
				"diffie-hellman-group1-sha1",
			},
		},
		{
			name: "permit root login",
			finding: models.Finding{
				HostIP:   "10.0.0.3",
				Port:     22,
				Category: "policy",
				Title:    "Root login permitted",
				Severity: models.SeverityHigh,
			},
			wantContains: []string{
				"PermitRootLogin",
				"PermitRootLogin no",
			},
		},
		{
			name: "password auth",
			finding: models.Finding{
				HostIP:   "10.0.0.4",
				Port:     22,
				Category: "policy",
				Title:    "Password authentication enabled",
				Severity: models.SeverityMedium,
			},
			wantContains: []string{
				"PasswordAuthentication no",
				"ChallengeResponseAuthentication",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := gen.Generate(&tt.finding)

			if script == "" {
				t.Fatal("expected non-empty remediation script")
			}

			for _, substr := range tt.wantContains {
				if !strings.Contains(script, substr) {
					t.Errorf("remediation script missing expected substring: %q\nGot:\n%s", substr, script)
				}
			}
		})
	}
}

func TestRemediationIdempotence(t *testing.T) {
	// Verify scripts use idempotent patterns
	gen := NewRemediationGenerator()

	finding := models.Finding{
		Category: "cipher",
		Title:    "Weak Cipher: 3des-cbc",
	}

	script := gen.Generate(&finding)

	// Should use sed -i or grep -q patterns for idempotence
	if !strings.Contains(script, "sed -i") && !strings.Contains(script, "grep -q") {
		t.Errorf("remediation should use idempotent patterns (sed -i / grep -q)")
	}

	// Should include backup
	if !strings.Contains(script, "cp") || !strings.Contains(script, ".bak") {
		t.Errorf("remediation should create backup before modifications")
	}

	// Should test config
	if !strings.Contains(script, "sshd -t") {
		t.Errorf("remediation should test config with 'sshd -t'")
	}
}

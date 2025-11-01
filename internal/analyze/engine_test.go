package analyze

import (
	"testing"

	"github.com/amariwan/ssh-hack/internal/models"
	"github.com/amariwan/ssh-hack/internal/storage"
	"github.com/amariwan/ssh-hack/internal/util"
)

func TestEngine_CheckKexAlgorithms(t *testing.T) {
	baseline := &storage.Baseline{}
	baseline.KexAlgorithms.Forbidden = []string{"diffie-hellman-group1-sha1"}
	baseline.KexAlgorithms.Deprecated = []string{"diffie-hellman-group14-sha1"}

	vulnDB := &storage.VulnDatabase{}
	logger := util.NewLogger("error")
	engine := NewEngine(baseline, vulnDB, logger)

	sshInfo := &models.SSHInfo{
		Host: models.Host{IP: []byte{127, 0, 0, 1}, Port: 22},
		KexAlgorithms: []string{
			"curve25519-sha256",
			"diffie-hellman-group1-sha1",  // forbidden
			"diffie-hellman-group14-sha1", // deprecated
		},
	}

	findings := engine.checkKexAlgorithms(sshInfo)

	// Should have 2 findings: 1 forbidden, 1 deprecated
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
	}

	// Check severity
	var criticalCount, mediumCount int
	for _, f := range findings {
		if f.Severity == models.SeverityCritical {
			criticalCount++
		}
		if f.Severity == models.SeverityMedium {
			mediumCount++
		}
	}

	if criticalCount != 1 {
		t.Errorf("Expected 1 critical finding, got %d", criticalCount)
	}
	if mediumCount != 1 {
		t.Errorf("Expected 1 medium finding, got %d", mediumCount)
	}
}

func TestEngine_CheckPolicy(t *testing.T) {
	baseline := &storage.Baseline{}
	baseline.Policies.PasswordAuthentication = false
	baseline.Policies.PermitRootLogin = "no"

	vulnDB := &storage.VulnDatabase{}
	logger := util.NewLogger("error")
	engine := NewEngine(baseline, vulnDB, logger)

	passwordAuth := true
	sshInfo := &models.SSHInfo{
		Host: models.Host{IP: []byte{127, 0, 0, 1}, Port: 22},
		Policy: &models.PolicyConfig{
			PasswordAuthentication: &passwordAuth,
			PermitRootLogin:        "yes",
		},
	}

	findings := engine.checkPolicy(sshInfo)

	// Should have 2 findings: password auth + root login
	if len(findings) < 2 {
		t.Errorf("Expected at least 2 findings, got %d", len(findings))
	}

	// Both should be high or critical severity
	for _, f := range findings {
		if f.Severity != models.SeverityHigh && f.Severity != models.SeverityCritical {
			t.Errorf("Expected high/critical severity, got %s", f.Severity)
		}
	}
}

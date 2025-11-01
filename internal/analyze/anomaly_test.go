package analyze

import (
	"net"
	"testing"
	"time"

	"github.com/amariwan/ssh-hack/internal/models"
)

func TestAnomalyDetector_Detect(t *testing.T) {
	detector := NewAnomalyDetector(3.0)

	// Create test data with outliers
	hosts := []models.SSHInfo{
		{Host: models.Host{IP: parseIP("10.0.0.1"), Port: 22, RTT: 10 * time.Millisecond}, HandshakeTime: 50 * time.Millisecond},
		{Host: models.Host{IP: parseIP("10.0.0.2"), Port: 22, RTT: 12 * time.Millisecond}, HandshakeTime: 52 * time.Millisecond},
		{Host: models.Host{IP: parseIP("10.0.0.3"), Port: 22, RTT: 11 * time.Millisecond}, HandshakeTime: 51 * time.Millisecond},
		{Host: models.Host{IP: parseIP("10.0.0.4"), Port: 22, RTT: 10 * time.Millisecond}, HandshakeTime: 49 * time.Millisecond},
		{Host: models.Host{IP: parseIP("10.0.0.5"), Port: 22, RTT: 11 * time.Millisecond}, HandshakeTime: 50 * time.Millisecond},
		// Outliers
		{Host: models.Host{IP: parseIP("10.0.0.99"), Port: 22, RTT: 500 * time.Millisecond}, HandshakeTime: 1000 * time.Millisecond},
	}

	findings := detector.Detect(hosts)

	if len(findings) == 0 {
		t.Fatal("expected anomaly findings, got none")
	}

	// Should detect outlier host
	foundOutlier := false
	for _, f := range findings {
		if f.HostIP == "10.0.0.99" && f.Category == "anomaly" {
			foundOutlier = true

			// Verify anomaly details
			if f.AnomalyDetails == nil {
				t.Error("anomaly finding missing AnomalyDetails")
			} else {
				if f.AnomalyDetails.ZScore <= 3.0 {
					t.Errorf("expected Z-score > 3.0, got %.2f", f.AnomalyDetails.ZScore)
				}
				if f.AnomalyDetails.DeviationPct <= 100 {
					t.Errorf("expected high deviation %%, got %.1f%%", f.AnomalyDetails.DeviationPct)
				}
			}
		}
	}

	if !foundOutlier {
		t.Error("did not detect outlier host 10.0.0.99")
	}

	// Normal hosts should not be flagged
	for _, f := range findings {
		if f.HostIP != "10.0.0.99" {
			t.Errorf("normal host %s incorrectly flagged as anomaly", f.HostIP)
		}
	}
}

func TestAnomalyDetector_SmallDataset(t *testing.T) {
	detector := NewAnomalyDetector(3.0)

	// Too few hosts for statistical analysis
	hosts := []models.SSHInfo{
		{Host: models.Host{IP: parseIP("10.0.0.1"), Port: 22, RTT: 10 * time.Millisecond}, HandshakeTime: 50 * time.Millisecond},
		{Host: models.Host{IP: parseIP("10.0.0.2"), Port: 22, RTT: 12 * time.Millisecond}, HandshakeTime: 52 * time.Millisecond},
	}

	findings := detector.Detect(hosts)

	// Should not panic, should return no findings
	if len(findings) > 0 {
		t.Errorf("expected no findings for small dataset, got %d", len(findings))
	}
}

func TestCalculateStats(t *testing.T) {
	detector := NewAnomalyDetector(3.0)

	data := []float64{10, 12, 11, 10, 13, 11, 12}

	stats := detector.calculateStats(data)

	// Check mean
	expectedMean := (10 + 12 + 11 + 10 + 13 + 11 + 12) / 7.0
	if stats.mean < expectedMean-0.1 || stats.mean > expectedMean+0.1 {
		t.Errorf("mean = %.2f, want ~%.2f", stats.mean, expectedMean)
	}

	// Check median
	if stats.median != 11.0 {
		t.Errorf("median = %.2f, want 11.0", stats.median)
	}

	// Check stdDev is positive
	if stats.stdDev <= 0 {
		t.Errorf("stdDev should be positive, got %.2f", stats.stdDev)
	}
}

func parseIP(s string) net.IP {
	// Helper to create IP for tests
	return net.ParseIP(s)
}

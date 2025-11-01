package analyze

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/amariwan/ssh-hack/internal/models"
)

// AnomalyDetector identifies outliers in SSH handshake metrics
type AnomalyDetector struct {
	threshold float64 // Z-score threshold (default: 3.0)
}

// NewAnomalyDetector creates a detector with threshold
func NewAnomalyDetector(threshold float64) *AnomalyDetector {
	if threshold == 0 {
		threshold = 3.0 // Default: 3 std deviations
	}
	return &AnomalyDetector{threshold: threshold}
}

// Detect finds anomalies in scan results
func (d *AnomalyDetector) Detect(hosts []models.SSHInfo) []models.Finding {
	var findings []models.Finding

	// Extract metrics
	rtts := make([]float64, 0, len(hosts))
	kexTimes := make([]float64, 0, len(hosts))
	hostMetrics := make(map[string]map[string]float64)

	for _, host := range hosts {
		key := fmt.Sprintf("%s:%d", host.Host.IP.String(), host.Host.Port)
		hostMetrics[key] = map[string]float64{
			"rtt":      host.Host.RTT.Seconds() * 1000, // Convert to ms
			"kex_time": host.HandshakeTime.Seconds() * 1000,
		}
		rtts = append(rtts, host.Host.RTT.Seconds()*1000)
		kexTimes = append(kexTimes, host.HandshakeTime.Seconds()*1000)
	}

	// Detect RTT anomalies
	if len(rtts) >= 5 {
		rttStats := d.calculateStats(rtts)
		for hostKey, metrics := range hostMetrics {
			rttValue := metrics["rtt"]
			zScore := (rttValue - rttStats.mean) / rttStats.stdDev

			if math.Abs(zScore) > d.threshold {
				findings = append(findings, d.createAnomalyFinding(
					hostKey, "rtt", rttValue, rttStats, zScore,
				))
			}
		}
	}

	// Detect KEX time anomalies
	if len(kexTimes) >= 5 {
		kexStats := d.calculateStats(kexTimes)
		for hostKey, metrics := range hostMetrics {
			kexValue := metrics["kex_time"]
			zScore := (kexValue - kexStats.mean) / kexStats.stdDev

			if math.Abs(zScore) > d.threshold {
				findings = append(findings, d.createAnomalyFinding(
					hostKey, "kex_duration", kexValue, kexStats, zScore,
				))
			}
		}
	}

	return findings
}

// createAnomalyFinding builds a finding for an anomaly
func (d *AnomalyDetector) createAnomalyFinding(
	hostKey, metricName string,
	observedValue float64,
	stats stats,
	zScore float64,
) models.Finding {
	deviationPct := math.Abs((observedValue - stats.mean) / stats.mean * 100)

	severity := models.SeverityMedium
	riskScore := 40
	if math.Abs(zScore) > 5.0 {
		severity = models.SeverityHigh
		riskScore = 70
	}

	description := fmt.Sprintf(
		"Host exhibits abnormal %s (%.2fms vs expected %.2fms ± %.2fms). "+
			"Deviation: %.1f%%. This may indicate network issues, rate limiting, or honeypot behavior.",
		metricName, observedValue, stats.mean, stats.stdDev, deviationPct,
	)

	return models.Finding{
		ID:          fmt.Sprintf("ANOMALY-%s-%s", metricName, hostKey),
		HostIP:      parseHostIP(hostKey),
		Port:        parseHostPort(hostKey),
		Category:    "anomaly",
		Title:       fmt.Sprintf("Anomalous %s Detected", metricName),
		Description: description,
		Severity:    severity,
		RiskScore:   riskScore,
		Remediation: "Investigate network path, check for rate limiting, or verify host legitimacy. Anomalies may indicate honeypots or compromised infrastructure.",
		Timestamp:   time.Now(),
		AnomalyDetails: &models.AnomalyDetails{
			MetricName:    metricName,
			ObservedValue: observedValue,
			ExpectedMean:  stats.mean,
			StandardDev:   stats.stdDev,
			ZScore:        zScore,
			DeviationPct:  deviationPct,
		},
	}
}

// stats holds statistical measures
type stats struct {
	mean   float64
	median float64
	stdDev float64
	mad    float64 // Median Absolute Deviation (robust)
}

// calculateStats computes mean, median, std dev using basic algorithms
func (d *AnomalyDetector) calculateStats(data []float64) stats {
	if len(data) == 0 {
		return stats{}
	}

	// Mean
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	mean := sum / float64(len(data))

	// Median
	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)
	median := sorted[len(sorted)/2]
	if len(sorted)%2 == 0 {
		median = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	}

	// Standard Deviation
	variance := 0.0
	for _, v := range data {
		variance += (v - mean) * (v - mean)
	}
	variance /= float64(len(data))
	stdDev := math.Sqrt(variance)

	// MAD (Median Absolute Deviation) - robust outlier detection
	deviations := make([]float64, len(data))
	for i, v := range data {
		deviations[i] = math.Abs(v - median)
	}
	sort.Float64s(deviations)
	mad := deviations[len(deviations)/2]

	return stats{
		mean:   mean,
		median: median,
		stdDev: stdDev,
		mad:    mad,
	}
}

// Helper functions to parse host key
func parseHostIP(hostKey string) string {
	// hostKey format: "IP:Port"
	for i := len(hostKey) - 1; i >= 0; i-- {
		if hostKey[i] == ':' {
			return hostKey[:i]
		}
	}
	return hostKey
}

func parseHostPort(hostKey string) int {
	// hostKey format: "IP:Port"
	port := 0
	for i := len(hostKey) - 1; i >= 0; i-- {
		if hostKey[i] == ':' {
			fmt.Sscanf(hostKey[i+1:], "%d", &port)
			return port
		}
	}
	return 22
}

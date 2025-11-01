package handshake

import (
	"regexp"
	"strings"

	"github.com/amariwan/ssh-hack/internal/models"
	"gopkg.in/yaml.v3"
)

// ImplementationPattern defines SSH implementation fingerprint
type ImplementationPattern struct {
	Type           models.ImplementationType `yaml:"type"`
	BannerRegex    []string                  `yaml:"banner_regex"`
	KexOrder       []string                  `yaml:"kex_order,omitempty"` // Expected KEX algorithm order
	VersionPattern string                    `yaml:"version_pattern,omitempty"`
	RiskModifier   int                       `yaml:"risk_modifier"` // +10 for exotic, 0 for mainstream
}

// Fingerprinter identifies SSH implementations
type Fingerprinter struct {
	patterns []ImplementationPattern
}

// NewFingerprinter creates a fingerprinter with patterns
func NewFingerprinter() *Fingerprinter {
	return &Fingerprinter{
		patterns: getDefaultPatterns(),
	}
}

// NewFingerprinterFromYAML loads patterns from YAML
func NewFingerprinterFromYAML(data []byte) (*Fingerprinter, error) {
	var patterns []ImplementationPattern
	if err := yaml.Unmarshal(data, &patterns); err != nil {
		return nil, err
	}
	return &Fingerprinter{patterns: patterns}, nil
}

// Identify detects SSH implementation from banner and KEX
func (f *Fingerprinter) Identify(banner string, kexAlgorithms []string) (models.ImplementationType, float64) {
	if banner == "" {
		return models.ImplUnknown, 0.0
	}

	for _, pattern := range f.patterns {
		confidence := f.matchPattern(pattern, banner, kexAlgorithms)
		if confidence > 0.5 {
			return pattern.Type, confidence
		}
	}

	return models.ImplUnknown, 0.0
}

// GetRiskModifier returns risk score adjustment for implementation
func (f *Fingerprinter) GetRiskModifier(implType models.ImplementationType) int {
	for _, pattern := range f.patterns {
		if pattern.Type == implType {
			return pattern.RiskModifier
		}
	}
	// Unknown implementation should be treated as higher risk by default
	if implType == models.ImplUnknown {
		return 10
	}
	return 0
}

// matchPattern calculates confidence score for a pattern
func (f *Fingerprinter) matchPattern(pattern ImplementationPattern, banner string, kexAlgorithms []string) float64 {
	var score float64

	// Banner match (weight: 70%)
	bannerMatch := false
	for _, regexStr := range pattern.BannerRegex {
		if matched, _ := regexp.MatchString(regexStr, banner); matched {
			bannerMatch = true
			score += 0.7
			break
		}
	}

	if !bannerMatch {
		return 0.0 // Banner must match
	}

	// KEX order match (weight: 30%)
	if len(pattern.KexOrder) > 0 && len(kexAlgorithms) > 0 {
		kexScore := f.kexOrderSimilarity(pattern.KexOrder, kexAlgorithms)
		score += 0.3 * kexScore
	} else if len(pattern.KexOrder) == 0 {
		// No KEX pattern defined, banner match is sufficient
		score += 0.3
	}

	return score
}

// kexOrderSimilarity computes similarity between expected and actual KEX order
func (f *Fingerprinter) kexOrderSimilarity(expected, actual []string) float64 {
	if len(expected) == 0 || len(actual) == 0 {
		return 0.0
	}

	matches := 0
	maxCheck := min(len(expected), len(actual), 5) // Check first 5 KEX algos

	for i := 0; i < maxCheck; i++ {
		if i < len(expected) && i < len(actual) && expected[i] == actual[i] {
			matches++
		}
	}

	return float64(matches) / float64(maxCheck)
}

// getDefaultPatterns returns built-in patterns
func getDefaultPatterns() []ImplementationPattern {
	return []ImplementationPattern{
		{
			Type:         models.ImplOpenSSH,
			BannerRegex:  []string{`OpenSSH_\d+\.\d+`, `SSH-2\.0-OpenSSH`},
			KexOrder:     []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256"},
			RiskModifier: 0, // Mainstream
		},
		{
			Type:         models.ImplDropbear,
			BannerRegex:  []string{`dropbear`, `SSH-2\.0-dropbear`},
			KexOrder:     []string{"curve25519-sha256@libssh.org", "ecdh-sha2-nistp521"},
			RiskModifier: 5, // Less scrutinized
		},
		{
			Type:         models.ImplLibSSH,
			BannerRegex:  []string{`libssh`, `SSH-2\.0-libssh`},
			KexOrder:     []string{"curve25519-sha256@libssh.org", "ecdh-sha2-nistp256"},
			RiskModifier: 8, // Known CVE history
		},
		{
			Type:         models.ImplTectia,
			BannerRegex:  []string{`SSH Tectia`, `SSH-2\.0-.*Tectia`},
			RiskModifier: 3,
		},
		{
			Type:         models.ImplCiscoIOS,
			BannerRegex:  []string{`Cisco`, `SSH-2\.0-Cisco`},
			RiskModifier: 5,
		},
	}
}

func min(vals ...int) int {
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

// ExtractVersion parses version from banner
func ExtractVersion(banner string) string {
	// Example: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
	parts := strings.Fields(banner)
	if len(parts) == 0 {
		return ""
	}

	versionPart := parts[0]
	if strings.HasPrefix(versionPart, "SSH-") {
		sshParts := strings.Split(versionPart, "-")
		if len(sshParts) >= 3 {
			return strings.Join(sshParts[2:], "-")
		}
	}

	return versionPart
}

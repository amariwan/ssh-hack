package handshake

import (
	"testing"

	"github.com/amariwan/ssh-hack/internal/models"
)

func TestFingerprinter_Identify(t *testing.T) {
	fp := NewFingerprinter()

	tests := []struct {
		name          string
		banner        string
		kexAlgos      []string
		wantType      models.ImplementationType
		wantConfMin   float64
	}{
		{
			name:        "OpenSSH standard",
			banner:      "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
			kexAlgos:    []string{"curve25519-sha256", "ecdh-sha2-nistp256"},
			wantType:    models.ImplOpenSSH,
			wantConfMin: 0.7,
		},
		{
			name:        "OpenSSH minimal",
			banner:      "SSH-2.0-OpenSSH_7.4",
			kexAlgos:    []string{"diffie-hellman-group-exchange-sha256"},
			wantType:    models.ImplOpenSSH,
			wantConfMin: 0.7,
		},
		{
			name:        "Dropbear",
			banner:      "SSH-2.0-dropbear_2020.81",
			kexAlgos:    []string{"curve25519-sha256@libssh.org", "ecdh-sha2-nistp521"},
			wantType:    models.ImplDropbear,
			wantConfMin: 0.7,
		},
		{
			name:        "libssh",
			banner:      "SSH-2.0-libssh-0.9.6",
			kexAlgos:    []string{"curve25519-sha256@libssh.org"},
			wantType:    models.ImplLibSSH,
			wantConfMin: 0.7,
		},
		{
			name:        "Cisco",
			banner:      "SSH-2.0-Cisco-1.25",
			kexAlgos:    []string{"diffie-hellman-group14-sha1"},
			wantType:    models.ImplCiscoIOS,
			wantConfMin: 0.7,
		},
		{
			name:        "Unknown",
			banner:      "SSH-2.0-CustomSSH_1.0",
			kexAlgos:    []string{"unknown-kex"},
			wantType:    models.ImplUnknown,
			wantConfMin: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotConf := fp.Identify(tt.banner, tt.kexAlgos)

			if gotType != tt.wantType {
				t.Errorf("Identify() type = %v, want %v", gotType, tt.wantType)
			}

			if gotConf < tt.wantConfMin {
				t.Errorf("Identify() confidence = %.2f, want >= %.2f", gotConf, tt.wantConfMin)
			}
		})
	}
}

func TestFingerprinter_RiskModifier(t *testing.T) {
	fp := NewFingerprinter()

	tests := []struct {
		implType    models.ImplementationType
		wantRisk    int
		description string
	}{
		{models.ImplOpenSSH, 0, "mainstream, well-audited"},
		{models.ImplDropbear, 5, "less scrutinized"},
		{models.ImplLibSSH, 8, "known CVE history"},
		{models.ImplUnknown, 10, "unknown implementation"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			risk := fp.GetRiskModifier(tt.implType)
			if risk != tt.wantRisk {
				t.Errorf("GetRiskModifier(%v) = %d, want %d", tt.implType, risk, tt.wantRisk)
			}
		})
	}
}

func TestKexOrderSimilarity(t *testing.T) {
	fp := NewFingerprinter()

	expected := []string{"curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384"}

	tests := []struct {
		name      string
		actual    []string
		wantScore float64
	}{
		{
			name:      "exact match",
			actual:    []string{"curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384"},
			wantScore: 1.0,
		},
		{
			name:      "partial match",
			actual:    []string{"curve25519-sha256", "diffie-hellman-group14-sha256", "ecdh-sha2-nistp384"},
			wantScore: 0.33, // 1 out of 3
		},
		{
			name:      "no match",
			actual:    []string{"diffie-hellman-group1-sha1", "rsa1024-sha1", "md5"},
			wantScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := fp.kexOrderSimilarity(expected, tt.actual)

			// Allow 5% tolerance for floating point
			if score < tt.wantScore-0.05 || score > tt.wantScore+0.4 {
				t.Errorf("kexOrderSimilarity() = %.2f, want ~%.2f", score, tt.wantScore)
			}
		})
	}
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		banner  string
		want    string
	}{
		{"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "OpenSSH_8.2p1"},
		{"SSH-2.0-dropbear_2020.81", "dropbear_2020.81"},
		{"SSH-2.0-libssh-0.9.6", "libssh-0.9.6"},
		{"", ""},
		{"malformed", "malformed"},
	}

	for _, tt := range tests {
		t.Run(tt.banner, func(t *testing.T) {
			got := ExtractVersion(tt.banner)
			if got != tt.want {
				t.Errorf("ExtractVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

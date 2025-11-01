package models

import (
	"net"
	"time"
)

// Host represents a discovered SSH server
type Host struct {
	IP        net.IP        `json:"ip"`
	Hostname  string        `json:"hostname,omitempty"`
	Port      int           `json:"port"`
	RTT       time.Duration `json:"rtt"`
	Banner    string        `json:"banner,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// SSHInfo contains SSH handshake and policy information
type SSHInfo struct {
	Host             Host                   `json:"host"`
	Version          string                 `json:"version"`
	KexAlgorithms    []string               `json:"kex_algorithms"`
	HostKeyAlgorithms []string              `json:"host_key_algorithms"`
	Ciphers          CipherList             `json:"ciphers"`
	MACs             MACList                `json:"macs"`
	Compression      []string               `json:"compression"`
	HostKeys         []HostKeyFingerprint   `json:"host_keys"`
	Policy           *PolicyConfig          `json:"policy,omitempty"`
	HandshakeTime    time.Duration          `json:"handshake_time"`
}

// CipherList contains client-to-server and server-to-client ciphers
type CipherList struct {
	ClientToServer []string `json:"client_to_server"`
	ServerToClient []string `json:"server_to_client"`
}

// MACList contains client-to-server and server-to-client MACs
type MACList struct {
	ClientToServer []string `json:"client_to_server"`
	ServerToClient []string `json:"server_to_client"`
}

// HostKeyFingerprint represents a host key and its fingerprints
type HostKeyFingerprint struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint_sha256"`
	FingerprintMD5 string `json:"fingerprint_md5,omitempty"`
	KeySize     int    `json:"key_size,omitempty"`
}

// PolicyConfig contains sshd_config policy parameters
type PolicyConfig struct {
	PasswordAuthentication  *bool    `json:"password_authentication,omitempty"`
	PubkeyAuthentication    *bool    `json:"pubkey_authentication,omitempty"`
	PermitRootLogin         string   `json:"permit_root_login,omitempty"`
	PermitEmptyPasswords    *bool    `json:"permit_empty_passwords,omitempty"`
	MaxAuthTries            *int     `json:"max_auth_tries,omitempty"`
	LoginGraceTime          *int     `json:"login_grace_time,omitempty"`
	AllowUsers              []string `json:"allow_users,omitempty"`
	AllowGroups             []string `json:"allow_groups,omitempty"`
	DenyUsers               []string `json:"deny_users,omitempty"`
	DenyGroups              []string `json:"deny_groups,omitempty"`
	AuthenticationMethods   []string `json:"authentication_methods,omitempty"`
	KexAlgorithms           []string `json:"kex_algorithms,omitempty"`
	Ciphers                 []string `json:"ciphers,omitempty"`
	MACs                    []string `json:"macs,omitempty"`
	HostKeyAlgorithms       []string `json:"host_key_algorithms,omitempty"`
}

// Finding represents a security finding
type Finding struct {
	ID          string       `json:"id"`
	HostIP      string       `json:"host_ip"`
	Port        int          `json:"port"`
	Category    string       `json:"category"` // "kex", "cipher", "mac", "policy", "version"
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Severity    SeverityLevel `json:"severity"`
	RiskScore   int          `json:"risk_score"` // 0-100
	Remediation string       `json:"remediation"`
	CVEs        []string     `json:"cves,omitempty"`
	Timestamp   time.Time    `json:"timestamp"`
}

// SeverityLevel represents risk severity
type SeverityLevel string

const (
	SeverityInfo     SeverityLevel = "info"
	SeverityLow      SeverityLevel = "low"
	SeverityMedium   SeverityLevel = "medium"
	SeverityHigh     SeverityLevel = "high"
	SeverityCritical SeverityLevel = "critical"
)

// Report aggregates all scan results
type Report struct {
	Metadata      ReportMetadata `json:"metadata"`
	Hosts         []SSHInfo      `json:"hosts"`
	Findings      []Finding      `json:"findings"`
	Summary       Summary        `json:"summary"`
	GeneratedAt   time.Time      `json:"generated_at"`
}

// ReportMetadata contains scan metadata
type ReportMetadata struct {
	ScanID        string    `json:"scan_id"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	Duration      time.Duration `json:"duration"`
	TargetRanges  []string  `json:"target_ranges"`
	Authorized    bool      `json:"authorized"`
	ToolVersion   string    `json:"tool_version"`
}

// Summary provides aggregated statistics
type Summary struct {
	TotalHosts           int            `json:"total_hosts"`
	TotalFindings        int            `json:"total_findings"`
	FindingsBySeverity   map[SeverityLevel]int `json:"findings_by_severity"`
	PasswordAuthEnabled  int            `json:"password_auth_enabled"`
	RootLoginPermitted   int            `json:"root_login_permitted"`
	WeakKexUsage         map[string]int `json:"weak_kex_usage"`
	WeakCipherUsage      map[string]int `json:"weak_cipher_usage"`
	WeakMACUsage         map[string]int `json:"weak_mac_usage"`
	CVECounts            map[string]int `json:"cve_counts"`
}

// ScanConfig holds scan configuration
type ScanConfig struct {
	Allowlist        []string
	Ports            []int
	Concurrency      int
	Timeout          time.Duration
	RateLimit        int // requests per second
	DNSReverse       bool
	DryRun           bool
	Authorized       bool
	CredentialsFile  string
	BaselineFile     string
	VulnsFile        string
	FailOnSeverity   SeverityLevel
}

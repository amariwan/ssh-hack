package storage

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Baseline defines security baseline for SSH configurations
type Baseline struct {
	KexAlgorithms struct {
		Allowed    []string `yaml:"allowed"`
		Deprecated []string `yaml:"deprecated"`
		Forbidden  []string `yaml:"forbidden"`
	} `yaml:"kex_algorithms"`

	Ciphers struct {
		Allowed    []string `yaml:"allowed"`
		Deprecated []string `yaml:"deprecated"`
		Forbidden  []string `yaml:"forbidden"`
	} `yaml:"ciphers"`

	MACs struct {
		Allowed    []string `yaml:"allowed"`
		Deprecated []string `yaml:"deprecated"`
		Forbidden  []string `yaml:"forbidden"`
	} `yaml:"macs"`

	HostKeys struct {
		Allowed     []string       `yaml:"allowed"`
		MinKeySizes map[string]int `yaml:"min_key_sizes"`
	} `yaml:"host_keys"`

	Policies struct {
		PasswordAuthentication bool   `yaml:"password_authentication"`
		PermitRootLogin        string `yaml:"permit_root_login"`
		MaxAuthTries           int    `yaml:"max_auth_tries"`
		PermitEmptyPasswords   bool   `yaml:"permit_empty_passwords"`
	} `yaml:"policies"`
}

// VulnDatabase maps SSH versions to CVEs
type VulnDatabase struct {
	Vulnerabilities []Vulnerability `yaml:"vulnerabilities"`
}

// Vulnerability represents a known CVE
type Vulnerability struct {
	CVE              string   `yaml:"cve"`
	Title            string   `yaml:"title"`
	Description      string   `yaml:"description"`
	Severity         string   `yaml:"severity"`
	AffectedVersions []string `yaml:"affected_versions"`
	FixedIn          string   `yaml:"fixed_in"`
}

// LoadBaseline loads baseline from YAML file
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline file: %w", err)
	}

	var baseline Baseline
	if err := yaml.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to parse baseline YAML: %w", err)
	}

	return &baseline, nil
}

// LoadVulnDatabase loads vulnerability database from YAML
func LoadVulnDatabase(path string) (*VulnDatabase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read vulns file: %w", err)
	}

	var db VulnDatabase
	if err := yaml.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse vulns YAML: %w", err)
	}

	return &db, nil
}

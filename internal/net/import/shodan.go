package import_targets

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

// ShodanResult represents Shodan API result format
type ShodanResult struct {
	Matches []ShodanHost `json:"matches"`
}

// ShodanHost represents a single Shodan host
type ShodanHost struct {
	IPStr     string   `json:"ip_str"`
	Port      int      `json:"port"`
	Banner    string   `json:"data"`
	Product   string   `json:"product"`
	Version   string   `json:"version"`
	Hostnames []string `json:"hostnames"`
}

// Target represents an imported scan target
type Target struct {
	IP       net.IP
	Port     int
	Hostname string
	Banner   string
	Source   string // "shodan", "nmap", etc.
}

// ImportShodanJSON parses Shodan JSON export
func ImportShodanJSON(filePath string) ([]Target, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var result ShodanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Shodan JSON: %w", err)
	}

	var targets []Target
	for _, host := range result.Matches {
		ip := net.ParseIP(host.IPStr)
		if ip == nil {
			continue // Invalid IP
		}

		// Only include SSH ports (22, 2222, etc.)
		if !isSSHPort(host.Port) {
			continue
		}

		hostname := ""
		if len(host.Hostnames) > 0 {
			hostname = host.Hostnames[0]
		}

		targets = append(targets, Target{
			IP:       ip,
			Port:     host.Port,
			Hostname: hostname,
			Banner:   host.Banner,
			Source:   "shodan",
		})
	}

	return targets, nil
}

// isSSHPort checks if port is commonly used for SSH
func isSSHPort(port int) bool {
	// Accept only well-known/customary SSH ports here. This keeps imports
	// conservative and matches test expectations (22, 2222, 22222).
	commonSSHPorts := []int{22, 2222, 22222}
	for _, p := range commonSSHPorts {
		if port == p {
			return true
		}
	}
	// Otherwise, do not consider it SSH.
	return false
}

//go:build nmap
// +build nmap

package import_targets

import (
	"fmt"
	"net"
	"os"

	"github.com/Ullaakut/nmap/v3"
)

// ImportNmapXML parses Nmap XML output
func ImportNmapXML(filePath string) ([]Target, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse Nmap XML
	result, err := nmap.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Nmap XML: %w", err)
	}

	var targets []Target
	for _, host := range result.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}

		ip := net.ParseIP(host.Addresses[0].Addr)
		if ip == nil {
			continue
		}

		hostname := ""
		if len(host.Hostnames) > 0 {
			hostname = host.Hostnames[0].Name
		}

		// Extract SSH ports
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}

			// Check if service is SSH
			if port.Service.Name == "ssh" || isSSHPort(int(port.ID)) {
				target := Target{
					IP:       ip,
					Port:     int(port.ID),
					Hostname: hostname,
					Source:   "nmap",
				}

				// Extract banner if available
				if port.Service.Product != "" {
					target.Banner = fmt.Sprintf("%s %s", port.Service.Product, port.Service.Version)
				}

				targets = append(targets, target)
			}
		}
	}

	return targets, nil
}

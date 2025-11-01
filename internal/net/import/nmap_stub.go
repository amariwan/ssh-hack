//go:build !nmap
// +build !nmap

package import_targets

import "fmt"

// ImportNmapXML is a stub when nmap build tag is not set
func ImportNmapXML(filePath string) ([]Target, error) {
	return nil, fmt.Errorf("Nmap import requires 'nmap' build tag: rebuild with 'go build -tags nmap'")
}

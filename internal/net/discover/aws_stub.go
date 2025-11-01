//go:build !cloud
// +build !cloud

package discover

import (
	"context"
	"fmt"

	import_targets "github.com/amariwan/ssh-hack/internal/net/import"
)

// AWSDiscoveryConfig stub
type AWSDiscoveryConfig struct {
	Region       string
	UsePublicIP  bool
	UsePrivateIP bool
}

// AWSDiscoverer stub
type AWSDiscoverer struct{}

// NewAWSDiscoverer stub
func NewAWSDiscoverer(cfg AWSDiscoveryConfig) (*AWSDiscoverer, error) {
	return nil, fmt.Errorf("AWS discovery requires 'cloud' build tag: rebuild with 'go build -tags cloud'")
}

// Discover stub
func (d *AWSDiscoverer) Discover(ctx context.Context) ([]import_targets.Target, error) {
	return nil, fmt.Errorf("AWS discovery not available")
}

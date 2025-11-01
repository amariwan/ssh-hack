//go:build cloud
// +build cloud

package discover

import (
	"context"
	"fmt"
	"net"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	import_targets "github.com/amariwan/ssh-hack/internal/net/import"
)

// AWSDiscoveryConfig holds AWS discovery parameters
type AWSDiscoveryConfig struct {
	Region          string
	UsePublicIP     bool
	UsePrivateIP    bool
	TagFilters      map[string]string // Optional: filter by tags
	IncludeStopped  bool
}

// AWSDiscoverer discovers EC2 instances
type AWSDiscoverer struct {
	config AWSDiscoveryConfig
	client *ec2.Client
}

// NewAWSDiscoverer creates an AWS EC2 discoverer
func NewAWSDiscoverer(cfg AWSDiscoveryConfig) (*AWSDiscoverer, error) {
	ctx := context.TODO()

	// Load AWS config
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := ec2.NewFromConfig(awsCfg)

	return &AWSDiscoverer{
		config: cfg,
		client: client,
	}, nil
}

// Discover fetches EC2 instances and returns SSH targets
func (d *AWSDiscoverer) Discover(ctx context.Context) ([]import_targets.Target, error) {
	// Build filters
	filters := []types.Filter{
		{
			Name:   stringPtr("instance-state-name"),
			Values: []string{"running"},
		},
	}

	if d.config.IncludeStopped {
		filters[0].Values = append(filters[0].Values, "stopped")
	}

	// Add tag filters
	for key, value := range d.config.TagFilters {
		filters = append(filters, types.Filter{
			Name:   stringPtr(fmt.Sprintf("tag:%s", key)),
			Values: []string{value},
		})
	}

	// Describe instances
	input := &ec2.DescribeInstancesInput{
		Filters: filters,
	}

	result, err := d.client.DescribeInstances(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("EC2 DescribeInstances failed: %w", err)
	}

	// Extract targets
	var targets []import_targets.Target
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			instanceTargets := d.extractTargets(instance)
			targets = append(targets, instanceTargets...)
		}
	}

	return targets, nil
}

// extractTargets converts EC2 instance to targets
func (d *AWSDiscoverer) extractTargets(instance types.Instance) []import_targets.Target {
	var targets []import_targets.Target

	instanceID := ""
	if instance.InstanceId != nil {
		instanceID = *instance.InstanceId
	}

	// Public IP
	if d.config.UsePublicIP && instance.PublicIpAddress != nil {
		ip := net.ParseIP(*instance.PublicIpAddress)
		if ip != nil {
			targets = append(targets, import_targets.Target{
				IP:       ip,
				Port:     22,
				Hostname: instanceID,
				Source:   "aws-ec2-public",
			})
		}
	}

	// Private IP
	if d.config.UsePrivateIP && instance.PrivateIpAddress != nil {
		ip := net.ParseIP(*instance.PrivateIpAddress)
		if ip != nil {
			targets = append(targets, import_targets.Target{
				IP:       ip,
				Port:     22,
				Hostname: instanceID,
				Source:   "aws-ec2-private",
			})
		}
	}

	return targets
}

func stringPtr(s string) *string {
	return &s
}

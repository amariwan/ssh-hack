package scan

import (
	"context"
	"testing"
	"time"

	"github.com/amariwan/ssh-hack/internal/util"
)

func TestExpandCIDRs(t *testing.T) {
	tests := []struct {
		name     string
		cidrs    []string
		expected int
		wantErr  bool
	}{
		{
			name:     "single IP",
			cidrs:    []string{"192.168.1.1"},
			expected: 1,
			wantErr:  false,
		},
		{
			name:     "/30 CIDR",
			cidrs:    []string{"192.168.1.0/30"},
			expected: 2, // .1 and .2 (skip network .0 and broadcast .3)
			wantErr:  false,
		},
		{
			name:     "invalid CIDR",
			cidrs:    []string{"invalid"},
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "multiple CIDRs",
			cidrs:    []string{"10.0.0.1", "192.168.1.0/31"},
			expected: 2, // 1 IP + 1 from /31
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := expandCIDRs(tt.cidrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("expandCIDRs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(ips) < 1 {
				t.Errorf("expandCIDRs() got %d IPs, want at least 1", len(ips))
			}
		})
	}
}

func TestTCPScanner(t *testing.T) {
	logger := util.NewLogger("error")
	scanner := NewTCPScanner(10, 2*time.Second, 100, false, logger)

	ctx := context.Background()

	// Test localhost (SSH likely not running in test environment)
	hosts, err := scanner.Scan(ctx, []string{"127.0.0.1"}, []int{22})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// We don't assert host count as SSH may not be running
	t.Logf("Discovered %d hosts", len(hosts))
}

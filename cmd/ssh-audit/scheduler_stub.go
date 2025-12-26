//go:build !sched
// +build !sched

package main

import (
	"context"
	"fmt"

	"github.com/amariwan/ssh-hack/internal/util"
)

// SchedulerConfig stub
type SchedulerConfig struct {
	CronExpr       string
	SlackWebhook   string
	AlertThreshold float64
	StoragePath    string
}

// Scheduler stub
type Scheduler struct{}

// NewScheduler stub
func NewScheduler(config SchedulerConfig, logger util.Logger) (*Scheduler, error) {
	return nil, fmt.Errorf("scheduler requires 'sched' build tag: rebuild with 'go build -tags sched'")
}

// Start stub
func (s *Scheduler) Start(ctx context.Context) error {
	return fmt.Errorf("scheduler not available")
}

package main

// extra flags and runtime variables used by root.go but not present in main.go
var (
	// UI / server
	serve bool

	// Import flags
	importShodan string
	importNmap   string

	// Scheduling / alerts
	schedule          string
	alertSlackWebhook string
	alertThreshold    float64

	// Cloud discovery
	cloudProvider string
	awsRegion     string
	awsPublicIP   bool
	awsPrivateIP  bool
)

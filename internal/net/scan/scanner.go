package scan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/amariwan/ssh-hack/internal/models"
	"github.com/amariwan/ssh-hack/internal/util"
	"golang.org/x/time/rate"
)

// Scanner discovers SSH hosts
type Scanner interface {
	Scan(ctx context.Context, targets []string, ports []int) ([]models.Host, error)
}

// TCPScanner implements TCP-connect based discovery
type TCPScanner struct {
	Concurrency int
	Timeout     time.Duration
	RateLimit   int
	DNSReverse  bool
	logger      util.Logger
	limiter     *rate.Limiter
}

// NewTCPScanner creates a new scanner
func NewTCPScanner(concurrency int, timeout time.Duration, rateLimit int, dnsReverse bool, logger util.Logger) *TCPScanner {
	limiter := rate.NewLimiter(rate.Limit(rateLimit), rateLimit)
	return &TCPScanner{
		Concurrency: concurrency,
		Timeout:     timeout,
		RateLimit:   rateLimit,
		DNSReverse:  dnsReverse,
		logger:      logger,
		limiter:     limiter,
	}
}

// Scan performs TCP-connect scan across CIDRs and ports
func (s *TCPScanner) Scan(ctx context.Context, targets []string, ports []int) ([]models.Host, error) {
	s.logger.Info("Starting TCP scan", "targets", targets, "ports", ports)

	// Expand CIDRs to individual IPs
	ips, err := expandCIDRs(targets)
	if err != nil {
		return nil, fmt.Errorf("failed to expand CIDRs: %w", err)
	}

	s.logger.Info("Expanded targets", "total_ips", len(ips), "ports", len(ports))

	// Create scan jobs
	type job struct {
		ip   net.IP
		port int
	}

	jobs := make(chan job, len(ips)*len(ports))
	for _, ip := range ips {
		for _, port := range ports {
			jobs <- job{ip: ip, port: port}
		}
	}
	close(jobs)

	// Process jobs concurrently
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		hosts []models.Host
	)

	for i := 0; i < s.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Rate limiting
				if err := s.limiter.Wait(ctx); err != nil {
					return
				}

				if host, ok := s.scanHost(ctx, j.ip, j.port); ok {
					mu.Lock()
					hosts = append(hosts, host)
					mu.Unlock()
					s.logger.Debug("Host discovered", "ip", j.ip, "port", j.port)
				}
			}
		}()
	}

	wg.Wait()
	s.logger.Info("Scan completed", "hosts_found", len(hosts))
	return hosts, nil
}

// scanHost attempts to connect and grab SSH banner
func (s *TCPScanner) scanHost(ctx context.Context, ip net.IP, port int) (models.Host, bool) {
	start := time.Now()
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	dialer := &net.Dialer{
		Timeout: s.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return models.Host{}, false
	}
	defer conn.Close()

	rtt := time.Since(start)

	// Read SSH banner (max 255 bytes, ends with \r\n)
	banner, err := readSSHBanner(conn, 5*time.Second)
	if err != nil {
		s.logger.Debug("Failed to read banner", "addr", addr, "error", err)
		return models.Host{}, false
	}

	// Validate it looks like SSH
	if !strings.HasPrefix(banner, "SSH-") {
		return models.Host{}, false
	}

	host := models.Host{
		IP:        ip,
		Port:      port,
		RTT:       rtt,
		Banner:    strings.TrimSpace(banner),
		Timestamp: time.Now(),
	}

	// Optional DNS reverse lookup
	if s.DNSReverse {
		if names, err := net.LookupAddr(ip.String()); err == nil && len(names) > 0 {
			host.Hostname = names[0]
		}
	}

	return host, true
}

// readSSHBanner reads SSH protocol banner from connection
func readSSHBanner(conn net.Conn, timeout time.Duration) (string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// expandCIDRs converts CIDR notation to list of IPs
func expandCIDRs(cidrs []string) ([]net.IP, error) {
	var ips []net.IP

	for _, cidr := range cidrs {
		// Check if it's a single IP or CIDR
		if !strings.Contains(cidr, "/") {
			ip := net.ParseIP(cidr)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP: %s", cidr)
			}
			ips = append(ips, ip)
			continue
		}

		// Parse CIDR
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %s: %w", cidr, err)
		}

		// Iterate through all IPs in CIDR
		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
			// Skip network and broadcast addresses for /24 or smaller
			if isNetworkOrBroadcast(ip, ipNet) {
				continue
			}
			ips = append(ips, copyIP(ip))
		}
	}

	return ips, nil
}

// inc increments IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// copyIP creates a copy of IP
func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// isNetworkOrBroadcast checks if IP is network or broadcast address
func isNetworkOrBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	// Network address
	if ip.Equal(ipNet.IP) {
		return true
	}

	// Broadcast address (for IPv4)
	if ip.To4() != nil {
		broadcast := make(net.IP, len(ip))
		copy(broadcast, ipNet.IP)
		for i := range broadcast {
			broadcast[i] |= ^ipNet.Mask[i]
		}
		if ip.Equal(broadcast) {
			return true
		}
	}

	return false
}

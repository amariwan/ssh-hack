package policy

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/amariwan/ssh-hack/internal/models"
	"github.com/amariwan/ssh-hack/internal/util"
	"golang.org/x/crypto/ssh"
)

// Checker retrieves SSH policy configuration
type Checker interface {
	Check(ctx context.Context, host models.Host, credentials *Credentials) (*models.PolicyConfig, error)
}

// Credentials for SSH authentication
type Credentials struct {
	Username   string
	Password   string
	PrivateKey []byte
}

// RemoteChecker fetches policy via SSH connection
type RemoteChecker struct {
	Timeout int
	logger  util.Logger
}

// NewRemoteChecker creates a new policy checker
func NewRemoteChecker(timeout int, logger util.Logger) *RemoteChecker {
	return &RemoteChecker{
		Timeout: timeout,
		logger:  logger,
	}
}

// Check retrieves policy configuration via SSH
func (c *RemoteChecker) Check(ctx context.Context, host models.Host, creds *Credentials) (*models.PolicyConfig, error) {
	if creds == nil {
		return nil, fmt.Errorf("credentials required for policy check")
	}

	c.logger.Debug("Checking SSH policy", "host", host.IP, "user", creds.Username)

	// Establish SSH connection
	client, err := c.connect(host, creds)
	if err != nil {
		return nil, fmt.Errorf("SSH connection failed: %w", err)
	}
	defer client.Close()

	// Try `sshd -T` first (most accurate)
	config, err := c.execSSHD_T(client)
	if err != nil {
		c.logger.Warn("sshd -T failed, falling back to config parse", "error", err)
		// Fallback: read sshd_config file
		config, err = c.readConfig(client)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve policy: %w", err)
		}
	}

	c.logger.Debug("Policy retrieved", "host", host.IP)
	return config, nil
}

// connect establishes SSH connection
func (c *RemoteChecker) connect(host models.Host, creds *Credentials) (*ssh.Client, error) {
	addr := fmt.Sprintf("%s:%d", host.IP.String(), host.Port)

	var authMethods []ssh.AuthMethod
	if creds.Password != "" {
		authMethods = append(authMethods, ssh.Password(creds.Password))
	}
	if len(creds.PrivateKey) > 0 {
		signer, err := ssh.ParsePrivateKey(creds.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	config := &ssh.ClientConfig{
		User:            creds.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Accept any host key
		Timeout:         0,                           // Use default
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// execSSHD_T executes `sshd -T` and parses output
func (c *RemoteChecker) execSSHD_T(client *ssh.Client) (*models.PolicyConfig, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	output, err := session.CombinedOutput("sshd -T")
	if err != nil {
		return nil, fmt.Errorf("sshd -T execution failed: %w", err)
	}

	return parseSSHD_T(string(output)), nil
}

// parseSSHD_T parses `sshd -T` output
func parseSSHD_T(output string) *models.PolicyConfig {
	config := &models.PolicyConfig{}
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := parts[1]

		switch key {
		case "passwordauthentication":
			val := parseBool(value)
			config.PasswordAuthentication = &val
		case "pubkeyauthentication":
			val := parseBool(value)
			config.PubkeyAuthentication = &val
		case "permitrootlogin":
			config.PermitRootLogin = value
		case "permitemptypasswords":
			val := parseBool(value)
			config.PermitEmptyPasswords = &val
		case "maxauthtries":
			val := parseInt(value)
			config.MaxAuthTries = &val
		case "logingracetime":
			val := parseInt(value)
			config.LoginGraceTime = &val
		case "allowusers":
			config.AllowUsers = parts[1:]
		case "allowgroups":
			config.AllowGroups = parts[1:]
		case "denyusers":
			config.DenyUsers = parts[1:]
		case "denygroups":
			config.DenyGroups = parts[1:]
		case "authenticationmethods":
			config.AuthenticationMethods = parts[1:]
		case "kexalgorithms":
			config.KexAlgorithms = parseList(value)
		case "ciphers":
			config.Ciphers = parseList(value)
		case "macs":
			config.MACs = parseList(value)
		case "hostkeyalgorithms":
			config.HostKeyAlgorithms = parseList(value)
		}
	}

	return config
}

// readConfig reads and parses sshd_config file
func (c *RemoteChecker) readConfig(client *ssh.Client) (*models.PolicyConfig, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	output, err := session.CombinedOutput("cat /etc/ssh/sshd_config")
	if err != nil {
		return nil, fmt.Errorf("failed to read sshd_config: %w", err)
	}

	return parseSSHDConfig(string(output)), nil
}

// parseSSHDConfig parses sshd_config file content
func parseSSHDConfig(content string) *models.PolicyConfig {
	config := &models.PolicyConfig{}
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := parts[1]

		switch key {
		case "passwordauthentication":
			val := parseBool(value)
			config.PasswordAuthentication = &val
		case "pubkeyauthentication":
			val := parseBool(value)
			config.PubkeyAuthentication = &val
		case "permitrootlogin":
			config.PermitRootLogin = value
		case "permitemptypasswords":
			val := parseBool(value)
			config.PermitEmptyPasswords = &val
		case "maxauthtries":
			val := parseInt(value)
			config.MaxAuthTries = &val
		case "logingracetime":
			val := parseInt(value)
			config.LoginGraceTime = &val
		case "allowusers":
			config.AllowUsers = parts[1:]
		case "allowgroups":
			config.AllowGroups = parts[1:]
		case "denyusers":
			config.DenyUsers = parts[1:]
		case "denygroups":
			config.DenyGroups = parts[1:]
		case "kexalgorithms":
			config.KexAlgorithms = parseList(value)
		case "ciphers":
			config.Ciphers = parseList(value)
		case "macs":
			config.MACs = parseList(value)
		}
	}

	return config
}

// Helper functions
func parseBool(s string) bool {
	return strings.ToLower(s) == "yes"
}

func parseInt(s string) int {
	val, _ := strconv.Atoi(s)
	return val
}

func parseList(s string) []string {
	return strings.Split(s, ",")
}

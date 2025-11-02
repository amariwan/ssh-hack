# 🔐 Enterprise SSH Inventory & Hardening Auditor v2.0

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Compliant-green.svg)](SECURITY.md)
[![Version](https://img.shields.io/badge/Version-2.0.0-blue.svg)](CHANGELOG.md)

**Professional SSH infrastructure security auditing tool** for enterprises and security teams.

## 🎯 Purpose

Systematically discover, analyze, and harden SSH infrastructure across networks:

- ✅ **Discovery**: Non-intrusive TCP-connect scanning (no SYN raw packets)
- ✅ **Crypto Analysis**: KEXINIT parsing, cipher/MAC/Kex validation
- ✅ **Policy Auditing**: `sshd -T` + `sshd_config` compliance checks
- ✅ **CVE Mapping**: Version → vulnerability correlation (offline DB)
- ✅ **Risk Scoring**: Baseline drift detection with 0-100 risk scores
- ✅ **Reporting**: JSON, Markdown, SARIF, **HTML dashboards** (NEW v2)
- ✅ **Zero-Trust**: Consent-gated, auditable, sanitized logging
- 🆕 **Remediation**: Auto-generated fix scripts (v2)
- 🆕 **Fingerprinting**: SSH implementation detection (OpenSSH, Dropbear, etc.)
- 🆕 **Anomaly Detection**: Statistical outliers (honeypots, rate limiting)
- 🆕 **Scheduling**: Periodic scans with Slack alerts (v2)
- 🆕 **Import**: Shodan/Nmap target lists (v2)
- 🆕 **Cloud Discovery**: AWS EC2 auto-discovery (v2)

## 🚨 Legal & Ethics

⚠️ **AUTHORIZED USE ONLY**

- Only scan networks/hosts you **own or have explicit written permission** to test
- No brute-force, no password guessing, no exploits
- Requires `--i-am-authorized` consent flag (hard gate)
- Fully auditable with structured JSON logs

**Unauthorized scanning is illegal.** Users are solely responsible for compliance with laws (CFAA, GDPR, etc.).

## 🚀 Quick Start

### Prerequisites

- Go 1.23+
- Linux/macOS/Windows
- (Optional) AWS credentials for cloud discovery

### Installation

```bash
# Clone repository
git clone https://github.com/amariwan/ssh-hack.git
cd ssh-hack

# Default build (core features)
go build -o ssh-audit ./cmd/ssh-audit

# Full build with all features
go build -tags "sched,nmap,cloud" -o ssh-audit ./cmd/ssh-audit

# Run basic scan
./ssh-audit \
  --allowlist 192.168.1.0/24 \
  --ports 22,2222 \
  --i-am-authorized \
  --output-json report.json \
  --output-html dashboard.html
```

### Docker

```bash
docker build -t ssh-audit .
docker run --rm -v $(pwd)/configs:/configs -v $(pwd)/reports:/reports \
  ssh-audit \
  --allowlist 10.0.0.0/24 \
  --i-am-authorized \
  --output-json /reports/audit.json \
  --output-html /reports/dashboard.html
```

## 📖 Usage

### Basic Scan

```bash
ssh-audit \
  --allowlist 10.0.1.0/24,10.0.2.0/24 \
  --ports 22 \
  --concurrency 100 \
  --timeout 5 \
  --i-am-authorized
```

### v2 Features

#### HTML Dashboard with Live Server

```bash
# Generate interactive HTML report
ssh-audit --allowlist 10.0.0.0/24 \
  --output-html dashboard.html \
  --serve \
  --i-am-authorized

# Opens http://localhost:8080 with D3.js charts
```

#### Import from Shodan

```bash
# Export from Shodan API
shodan search "port:22" --fields ip_str,port,data,hostnames > shodan.json

# Import targets
ssh-audit --import-shodan shodan.json --i-am-authorized
```

#### Import from Nmap (requires 'nmap' build tag)

```bash
# Scan with Nmap
nmap -sV -p 22,2222 10.0.0.0/24 -oX scan.xml

# Import and analyze
go build -tags nmap -o ssh-audit ./cmd/ssh-audit
./ssh-audit --import-nmap-xml scan.xml --i-am-authorized
```

#### Scheduled Scans with Alerts (requires 'sched' build tag)

```bash
# Build with scheduler
go build -tags sched -o ssh-audit ./cmd/ssh-audit

# Run daily at 3 AM, alert on 10% score drop
./ssh-audit \
  --allowlist 10.0.0.0/24 \
  --schedule "0 3 * * *" \
  --alert-slack-webhook https://hooks.slack.com/services/XXX \
  --alert-threshold 10.0 \
  --i-am-authorized

# Stores trends in sqlite, runs continuously
```

#### AWS EC2 Discovery (requires 'cloud' build tag)

```bash
# Build with cloud support
go build -tags cloud -o ssh-audit ./cmd/ssh-audit

# Discover EC2 instances
export AWS_REGION=us-east-1
./ssh-audit \
  --provider aws \
  --aws-region us-east-1 \
  --aws-public-ip \
  --i-am-authorized
```

### Advanced Options

```bash
ssh-audit \
  --allowlist 192.168.0.0/16 \
  --ports 22,2222,8022 \
  --concurrency 200 \
  --rate-limit 500 \
  --timeout 10 \
  --dns-reverse \
  --baseline configs/baseline.yml \
  --vulns configs/vulns.yml \
  --output-json reports/scan.json \
  --output-markdown reports/scan.md \
  --output-sarif reports/scan.sarif \
  --output-html reports/dashboard.html \
  --fail-on high \
  --log-level debug \
  --i-am-authorized
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: SSH Security Audit
  run: |
    go build -o ssh-audit ./cmd/ssh-audit
    ./ssh-audit \
      --allowlist ${{ secrets.PROD_CIDR }} \
      --i-am-authorized \
      --output-sarif results.sarif \
      --output-html dashboard.html \
      --fail-on critical

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif

- name: Upload HTML Dashboard
  uses: actions/upload-artifact@v3
  with:
    name: ssh-audit-dashboard
    path: dashboard.html
```

## 🏗️ Architecture

```
ssh-hack/
├── cmd/ssh-audit/          # CLI entrypoint
├── internal/
│   ├── models/             # Data structures
│   ├── net/scan/           # TCP discovery
│   ├── ssh/
│   │   ├── handshake/      # KEXINIT analysis
│   │   └── policy/         # sshd config parsing
│   ├── analyze/            # Scoring engine
│   ├── report/             # JSON/Markdown/SARIF
│   ├── storage/            # Baseline/Vuln DB
│   └── util/               # Logging, sanitization
├── configs/
│   ├── baseline.yml        # Security baseline
│   └── vulns.yml           # CVE database
└── Dockerfile
```

## 📊 Baseline Configuration

Customize security policies in `configs/baseline.yml`:

```yaml
kex_algorithms:
  allowed:
    - curve25519-sha256
    - ecdh-sha2-nistp256
  forbidden:
    - diffie-hellman-group1-sha1

ciphers:
  allowed:
    - chacha20-poly1305@openssh.com
    - aes256-gcm@openssh.com
  forbidden:
    - 3des-cbc
    - arcfour

policies:
  password_authentication: false
  permit_root_login: "no"
  max_auth_tries: 3
```

## 🔍 Features

### Discovery

- IPv4/IPv6 CIDR expansion
- Concurrent TCP-connect scanning (no root required)
- Banner grabbing + normalization
- Optional DNS reverse lookup
- Rate limiting + jitter

### SSH Analysis

- **Handshake**: KEXINIT parsing (Kex, Ciphers, MACs, Compression)
- **Host Keys**: SHA256/MD5 fingerprints, key sizes
- **Policy**: Remote `sshd -T` execution or config file parsing
- **Timing**: RTT, handshake duration

### Scoring

- Baseline comparison (allowed/deprecated/forbidden)
- CVE mapping from offline database
- Risk scores (0-100) + severity levels
- Category-based findings (kex, cipher, mac, policy, version)

### Reporting

- **JSON**: Machine-readable, full detail
- **Markdown**: Human-friendly executive summary
- **SARIF**: Static Analysis Results Interchange Format (for GitHub Security, GitLab, etc.)
- **Summary**: Aggregated stats (% password auth, top weak algos, CVEs)

### Security

- Consent gate (`--i-am-authorized`)
- Sanitized logs (redacts keys, passwords, tokens)
- No credential storage
- Dry-run mode (`--dry-run`)
- Exit codes for CI gates

## 🛡️ Security Considerations

1. **No Exploits**: This tool performs **passive reconnaissance** only
2. **Credentials**: Only used for authorized policy checks (never stored)
3. **Logging**: All logs sanitized before output (see `internal/util/logger.go`)
4. **Allowlist**: Hard requirement prevents accidental wide scans
5. **Auditable**: Structured JSON logs with full context

## 🐳 Container Deployment

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o ssh-audit ./cmd/ssh-audit

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/ssh-audit /usr/local/bin/
COPY configs /configs
USER nobody
ENTRYPOINT ["ssh-audit"]
```

## 📈 Roadmap

- [ ] Policy checks via SSH (credentials support)
- [ ] Prometheus/OTel metrics export
- [ ] HTML report generation
- [ ] gRPC API for programmatic access
- [ ] Kubernetes operator for continuous auditing
- [ ] SBOM generation (Syft/CycloneDX)
- [ ] ARM64 builds

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/awesome`)
3. Commit changes (`git commit -am 'Add awesome feature'`)
4. Push to branch (`git push origin feature/awesome`)
5. Open Pull Request

**Guidelines**:
- Follow Go conventions (`gofmt`, `golint`)
- Add unit tests
- Update README/docs

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- OpenSSH team for protocol documentation
- Go `x/crypto/ssh` maintainers
- NIST/CIS for SSH hardening guides

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/amariwan/ssh-hack/issues)
- **Discussions**: [GitHub Discussions](https://github.com/amariwan/ssh-hack/discussions)
- **Security**: See [SECURITY.md](SECURITY.md)

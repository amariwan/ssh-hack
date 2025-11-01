# Multi-stage build for minimal final image
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build binary (static linking)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always --dirty)" \
    -o ssh-audit \
    ./cmd/ssh-audit

# Final stage - minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/ssh-audit /usr/local/bin/ssh-audit

# Copy default configs
COPY --chown=appuser:appgroup configs /app/configs

# Create output directory
RUN mkdir -p /app/reports && chown -R appuser:appgroup /app/reports

# Switch to non-root user
USER appuser

# Default entrypoint
ENTRYPOINT ["ssh-audit"]

# Default help command
CMD ["--help"]

# Health check (optional - for container orchestration)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/ssh-audit", "--help"] || exit 1

# Labels for metadata
LABEL org.opencontainers.image.title="SSH Security Auditor"
LABEL org.opencontainers.image.description="Enterprise SSH infrastructure security auditing tool"
LABEL org.opencontainers.image.authors="amariwan"
LABEL org.opencontainers.image.source="https://github.com/amariwan/ssh-hack"
LABEL org.opencontainers.image.licenses="MIT"

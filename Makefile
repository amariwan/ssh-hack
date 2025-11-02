.PHONY: build test clean run docker-build docker-run lint fmt vet

# Binary name
BINARY=ssh-audit
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-w -s -X main.version=$(VERSION)"

# Build directories
BUILD_DIR=build
DIST_DIR=dist

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
GOFMT=$(GOCMD) fmt
GOMOD=$(GOCMD) mod

# Build the binary
build:
	@echo "🔨 Building $(BINARY) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	# Prefer building from ./cmd/ssh-audit if present, otherwise fall back to ./main.go
	if [ -d "./cmd/ssh-audit" ] || [ -f "./cmd/ssh-audit/main.go" ]; then \
		$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/ssh-audit; \
	elif [ -f "./main.go" ]; then \
		$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./main.go; \
	else \
		echo "No main package found at ./cmd/ssh-audit or ./main.go"; exit 1; \
	fi
	@echo "✅ Build complete: $(BUILD_DIR)/$(BINARY)"

# Run tests
test:
	@echo "🧪 Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	@echo "✅ Tests complete"

# Run linter
lint:
	@echo "🔍 Running linter..."
	golangci-lint run ./...
	@echo "✅ Lint complete"

# Format code
fmt:
	@echo "🎨 Formatting code..."
	$(GOFMT) ./...
	@echo "✅ Format complete"

# Run go vet
vet:
	@echo "🔎 Running go vet..."
	$(GOVET) ./...
	@echo "✅ Vet complete"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	rm -rf $(BUILD_DIR) $(DIST_DIR) coverage.out *.json *.md *.sarif
	@echo "✅ Clean complete"

# Run the application
run: build
	@echo "🚀 Running $(BINARY)..."
	$(BUILD_DIR)/$(BINARY) --help

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "✅ Dependencies installed"

# Build Docker image
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t $(BINARY):$(VERSION) .
	docker tag $(BINARY):$(VERSION) $(BINARY):latest
	@echo "✅ Docker image built"

# Run Docker container
docker-run:
	@echo "🐳 Running Docker container..."
	docker run --rm -v $(PWD)/configs:/app/configs -v $(PWD)/reports:/app/reports \
		$(BINARY):latest --help

# Cross-compile for multiple platforms
dist:
	@echo "📦 Building distribution packages..."
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY)-linux-amd64 ./cmd/ssh-audit
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY)-linux-arm64 ./cmd/ssh-audit
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY)-darwin-amd64 ./cmd/ssh-audit
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY)-darwin-arm64 ./cmd/ssh-audit
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY)-windows-amd64.exe ./cmd/ssh-audit
	@echo "✅ Distribution packages built in $(DIST_DIR)/"

# Run example scan
example: build
	@echo "🔬 Running example scan..."
	$(BUILD_DIR)/$(BINARY) \
		--allowlist 127.0.0.1 \
		--ports 22 \
		--i-am-authorized \
		--dry-run \
		--log-level debug

# All quality checks
check: fmt vet lint test
	@echo "✅ All checks passed"

# Help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  test          - Run tests"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"
	@echo "  vet           - Run go vet"
	@echo "  clean         - Clean build artifacts"
	@echo "  run           - Build and run"
	@echo "  deps          - Install dependencies"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  dist          - Cross-compile for all platforms"
	@echo "  example       - Run example scan"
	@echo "  check         - Run all quality checks"
	@echo "  help          - Show this help"

.DEFAULT_GOAL := build

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=agent
BINARY_UNIX=$(BINARY_NAME)_unix

# Build the application
.PHONY: build
build:
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd/agent

# Build for Linux
.PHONY: build-linux
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v ./cmd/agent

# Clean build artifacts
.PHONY: clean
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

# Run the application
.PHONY: run
run:
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd/agent
	./$(BINARY_NAME)

# Run tests
.PHONY: test
test:
	$(GOTEST) -v ./...

# Run tests in Docker
#
# TEST_IMAGE is overridable: on a persistent machine a fixed tag can be
# overwritten by a concurrent run of the same target. See the note in
# backend/Makefile.
TEST_IMAGE ?= orchestrator-agent-test

.PHONY: test-docker
test-docker:
	@echo "Building test Docker image..."
	docker build -f Dockerfile.test -t $(TEST_IMAGE) .
	@echo "Running tests in Docker..."
	docker run --rm $(TEST_IMAGE)

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out

# Download dependencies
.PHONY: deps
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Format code
.PHONY: fmt
fmt:
	$(GOCMD) fmt ./...

# Lint code
.PHONY: lint
lint:
	golangci-lint run

# Build Debian package for ARM Linux using goreleaser
.PHONY: deb-arm
deb-arm:
	@echo "Building ARM Linux Debian package with GoReleaser..."
	@which goreleaser > /dev/null || (echo "Error: goreleaser not found. Install it with: go install github.com/goreleaser/goreleaser@latest" && exit 1)
	@echo "Building for Linux ARM64 only..."
	@GOOS=linux GOARCH=arm64 goreleaser release --snapshot --clean 
	@echo ""
	@echo "Debian package built in dist/ directory:"
	@find dist -name '*_linux_arm64.deb' 2>/dev/null | head -1 | xargs -I {} echo "  ARM64: {}" || echo "  ARM64: Not found (check dist/ directory)"

# Help
.PHONY: help
help:
	@echo "Available commands:"
	@echo "  build          - Build the application"
	@echo "  build-linux    - Build for Linux"
	@echo "  deb-arm        - Build ARM Linux Debian package (snapshot)"
	@echo "  clean          - Clean build artifacts"
	@echo "  run            - Run the application"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  deps           - Download dependencies"
	@echo "  fmt            - Format code"
	@echo "  lint           - Lint code"
	@echo "  help           - Show this help message"

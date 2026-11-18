# Proto Makefile
# Generates Go code from proto files for both agent and backend modules

.PHONY: generate clean tools help check-tools

PROTO_FILE = orchestrator.proto
GENERATED_FILES = orchestrator.pb.go orchestrator_grpc.pb.go
AGENT_DIR = ../agent
BACKEND_DIR = ../backend
AGENT_PROTO_DIR = $(AGENT_DIR)/pkg/infrastructure/grpc/proto
BACKEND_PROTO_DIR = $(BACKEND_DIR)/pkg/webapp/infrastructure/grpc/proto

# Check if required tools are installed
check-tools:
	@echo "Checking required tools..."
	@if ! command -v protoc &> /dev/null; then \
		echo "Error: protoc not found. Please install protoc via system package manager."; \
		exit 1; \
	fi
	@GOPATH_BIN=$$(go env GOPATH 2>/dev/null || echo ""); \
	HOME_GO_BIN=$$HOME/go/bin; \
	GO_BIN_PATH=""; \
	if [ -n "$$GOPATH_BIN" ] && [ -d "$$GOPATH_BIN/bin" ]; then \
		GO_BIN_PATH="$$GOPATH_BIN/bin"; \
	fi; \
	if [ -d "$$HOME_GO_BIN" ]; then \
		if [ -n "$$GO_BIN_PATH" ]; then \
			GO_BIN_PATH="$$GO_BIN_PATH:$$HOME_GO_BIN"; \
		else \
			GO_BIN_PATH="$$HOME_GO_BIN"; \
		fi; \
	fi; \
	ENHANCED_PATH="$$GO_BIN_PATH:$$PATH"; \
	MISSING_TOOLS=""; \
	if ! PATH="$$ENHANCED_PATH" command -v protoc-gen-go &> /dev/null; then \
		MISSING_TOOLS="protoc-gen-go"; \
	fi; \
	if ! PATH="$$ENHANCED_PATH" command -v protoc-gen-go-grpc &> /dev/null; then \
		if [ -n "$$MISSING_TOOLS" ]; then \
			MISSING_TOOLS="$$MISSING_TOOLS, protoc-gen-go-grpc"; \
		else \
			MISSING_TOOLS="protoc-gen-go-grpc"; \
		fi; \
	fi; \
	if [ -n "$$MISSING_TOOLS" ]; then \
		echo "Error: Missing required tools: $$MISSING_TOOLS"; \
		echo "Please run 'make proto/tools' first to install them."; \
		exit 1; \
	fi; \
	echo "All required tools are installed."

# Generate Go code from proto files and copy to agent/backend modules
generate: check-tools
	@echo "Generating gRPC code..."
	@GOPATH_BIN=$$(go env GOPATH 2>/dev/null || echo ""); \
	HOME_GO_BIN=$$HOME/go/bin; \
	GO_BIN_PATH=""; \
	if [ -n "$$GOPATH_BIN" ] && [ -d "$$GOPATH_BIN/bin" ]; then \
		GO_BIN_PATH="$$GOPATH_BIN/bin"; \
	fi; \
	if [ -d "$$HOME_GO_BIN" ]; then \
		if [ -n "$$GO_BIN_PATH" ]; then \
			GO_BIN_PATH="$$GO_BIN_PATH:$$HOME_GO_BIN"; \
		else \
			GO_BIN_PATH="$$HOME_GO_BIN"; \
		fi; \
	fi; \
	ENHANCED_PATH="$$GO_BIN_PATH:$$PATH"; \
	PATH="$$ENHANCED_PATH" protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_FILE)
	@echo "Generated files:"
	@for file in $(GENERATED_FILES); do \
		if [ -f "$$file" ]; then \
			echo "- $$file"; \
		fi; \
	done
	@echo ""
	@echo "Copying generated files to modules..."
	@mkdir -p $(AGENT_PROTO_DIR)
	@mkdir -p $(BACKEND_PROTO_DIR)
	@for file in $(GENERATED_FILES); do \
		if [ -f "$$file" ]; then \
			cp "$$file" $(AGENT_PROTO_DIR)/; \
			cp "$$file" $(BACKEND_PROTO_DIR)/; \
			echo "Copied $$file to agent and backend"; \
		else \
			echo "Warning: $$file not found, skipping..."; \
		fi; \
	done
	@echo "Done! Generated files copied to both modules."

# Clean generated files (from proto directory only)
clean:
	@echo "Cleaning generated files from proto directory..."
	@for file in $(GENERATED_FILES); do \
		if [ -f "$$file" ]; then \
			rm -f "$$file"; \
			echo "Removed $$file"; \
		fi; \
	done
	@echo "Cleanup complete!"

# Install development tools (proto generators).
# The versions are pinned because the generated files are committed in three
# places and must stay byte-identical: an unpinned generator makes two
# machines regenerate different headers from the same .proto, and the copy
# check (tools/publication-guard/check_proto_copies.sh) reads these pins.
PROTOC_GEN_GO_VERSION ?= v1.36.11
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.2

tools:
	@echo "Installing proto development tools..."
	@echo "Installing protoc-gen-go $(PROTOC_GEN_GO_VERSION)..."
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	@echo "Installing protoc-gen-go-grpc $(PROTOC_GEN_GO_GRPC_VERSION)..."
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
	@echo "Tools installed successfully!"
	@echo "Note: protoc must be installed separately via system package manager"

# Help
help:
	@echo "Available commands:"
	@echo "  generate    - Generate Go code from proto files and copy to agent/backend modules"
	@echo "  clean       - Remove generated .go files from proto directory"
	@echo "  tools       - Install development tools (protoc-gen-go, protoc-gen-go-grpc)"
	@echo "  check-tools - Check if all required tools are installed"
	@echo "  help        - Show this help message"

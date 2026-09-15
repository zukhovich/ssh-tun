BINARY_NAME := ssh-tun
VERSION := 1.0.3
BUILD_DIR := ./build
LDFLAGS := -trimpath -ldflags "-X main.Version=$(VERSION) -s -w -extldflags=-static"
MAIN_PACKAGE := ./cmd/ssh-tun

GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOVET := $(GOCMD) vet

.PHONY: all build clean test vet tidy run help

all: test build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 GOOS=linux $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

build-linux-amd64:
	@echo "Building for Linux amd64..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)_$(VERSION)_linux_amd64 $(MAIN_PACKAGE)

build-linux-arm64:
	@echo "Building for Linux arm64..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)_$(VERSION)_linux_arm64 $(MAIN_PACKAGE)

build-release: build-linux-amd64 build-linux-arm64
	@echo "Release build complete: $(VERSION)"
	@ls -la $(BUILD_DIR)/$(BINARY_NAME)_$(VERSION)_linux_*

package-release: build-release
	@echo "Packaging release files..."
	@cd $(BUILD_DIR) && \
	for file in $(BINARY_NAME)_$(VERSION)_linux_*; do \
	    if [ -f "$$file" ]; then \
	        tar -czf "$$file.tar.gz" "$$file"; \
	        echo "Packaged: $$file"; \
	    fi; \
	done
	@cd $(BUILD_DIR) && sha256sum $(BINARY_NAME)_$(VERSION)_linux_*.tar.gz > SHA256SUMS
	@echo "Packaging complete"

clean:
	@echo "Cleaning..."
	@$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

test:
	@echo "Running tests..."
	@$(GOTEST) -v ./...

vet:
	@echo "Running go vet..."
	@$(GOVET) ./...

tidy:
	@echo "Tidying modules..."
	@$(GOMOD) tidy

run:
	@$(GOCMD) run $(MAIN_PACKAGE)

version:
	@echo "Current version: $(VERSION)"

help:
	@echo "Make targets:"
	@echo "  build             - Build a static ssh-tun binary for Linux"
	@echo "  build-linux-amd64 - Build for Linux amd64"
	@echo "  build-linux-arm64 - Build for Linux arm64"
	@echo "  build-release     - Build all Linux release binaries"
	@echo "  package-release   - Build and package release archives"
	@echo "  clean             - Remove build artifacts"
	@echo "  test              - Run tests"
	@echo "  vet               - Run go vet"
	@echo "  tidy              - Tidy Go modules"
	@echo "  run               - Run the application"
	@echo "  version           - Print the current version"
	@echo "  help              - Print this help"

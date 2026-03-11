.PHONY: build run test clean fmt lint swagger docker help

# Build variables
BINARY_NAME=mid-bootstrap-server
BINARY_DIR=bin
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Full binary path
BINARY=$(BINARY_DIR)/$(BINARY_NAME).$(GOOS)-$(GOARCH).bin

# Default target
all: build

## build: Build the binary to bin/
build:
	@echo "Building $(BINARY)..."
	@mkdir -p $(BINARY_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) -o $(BINARY) .
	@echo "Built: $(BINARY)"

## build-all: Build for all platforms
build-all:
	@mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME).linux-amd64.bin .
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME).linux-arm64.bin .
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME).darwin-amd64.bin .
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME).darwin-arm64.bin .
	@echo "Built all platforms in $(BINARY_DIR)/"

## run: Run the server (requires VAULT_ADDR and VAULT_TOKEN)
run: build
	$(BINARY) -listen :8443

## run-dev: Run with development settings (no TLS, verbose)
run-dev: build
	$(BINARY) \
		-listen :8080 \
		-vault-addr $${VAULT_ADDR:-http://127.0.0.1:8200} \
		-trust-domain example.org

## test: Run tests
test:
	go test -v ./...

## test-cover: Run tests with coverage
test-cover:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## fmt: Format code
fmt:
	go fmt ./...

## lint: Run linter
lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

## vet: Run go vet
vet:
	go vet ./...

## tidy: Tidy dependencies
tidy:
	go mod tidy

## swagger: Generate Swagger documentation
swagger:
	@which swag > /dev/null || (echo "Installing swag..." && go install github.com/swaggo/swag/cmd/swag@latest)
	swag init --parseDependency --parseInternal
	@echo "Swagger docs generated in docs/"

## clean: Clean build artifacts
clean:
	rm -f $(BINARY_DIR)/*.bin
	rm -f coverage.out coverage.html

## docker-build: Build Docker image
docker-build:
	docker build -t $(BINARY_NAME):$(VERSION) .

## docker-run: Run in Docker
docker-run:
	docker run -p 8443:8443 \
		-e VAULT_ADDR=$${VAULT_ADDR} \
		-e VAULT_TOKEN=$${VAULT_TOKEN} \
		-e TRUST_DOMAIN=$${TRUST_DOMAIN:-example.org} \
		$(BINARY_NAME):$(VERSION)

## curl-health: Test health endpoint
curl-health:
	curl -s http://localhost:8080/health | jq .

## curl-version: Get server version
curl-version:
	curl -s http://localhost:8080/version | jq .

## curl-swagger: Get Swagger JSON spec
curl-swagger:
	curl -s http://localhost:8080/swagger/doc.json | jq .

## curl-stats: Get dashboard stats
curl-stats:
	curl -s http://localhost:8080/api/stats | jq .

## curl-requests: List all requests
curl-requests:
	curl -s http://localhost:8080/api/requests | jq .

## curl-pending: List pending requests
curl-pending:
	curl -s 'http://localhost:8080/api/requests?status=pending' | jq .

## simulate-agent: Simulate an agent bootstrap request
simulate-agent:
	curl -s -X POST http://localhost:8080/bootstrap/linux/machine \
		-H "Content-Type: application/json" \
		-d '{"hostname":"test-agent-01","ip_addresses":["10.0.1.100"],"mac_addresses":["00:11:22:33:44:55"],"os":"linux","arch":"amd64","os_version":"Ubuntu 22.04","uptime_seconds":3600}' | jq .

## approve: Approve a request (usage: make approve ID=<request-id>)
approve:
	@if [ -z "$(ID)" ]; then echo "Usage: make approve ID=<request-id>"; exit 1; fi
	curl -s -X POST http://localhost:8080/api/approve \
		-H "Content-Type: application/json" \
		-d '{"request_id":"$(ID)","approved_by":"operator"}' | jq .

## deny: Deny a request (usage: make deny ID=<request-id> REASON="reason")
deny:
	@if [ -z "$(ID)" ]; then echo "Usage: make deny ID=<request-id> REASON=\"reason\""; exit 1; fi
	curl -s -X POST http://localhost:8080/api/deny \
		-H "Content-Type: application/json" \
		-d '{"request_id":"$(ID)","denied_by":"operator","reason":"$(REASON)"}' | jq .

## help: Show this help
help:
	@echo "MID Bootstrap Server"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /' | column -t -s ':'

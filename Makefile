BINARY  := vulnscan
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test test-v check fmt lint coverage clean help

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/vulnscan

test:
	go test -race ./...

test-v:
	go test -v -race ./...

check: fmt
	go vet ./...
	go test -race ./...

fmt:
	gofmt -w .

## lint: Run golangci-lint if installed
lint:
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed; skipping"

## coverage: Run tests with coverage and open an HTML profile
coverage:
	@mkdir -p bin
	go test -race -coverprofile=bin/coverage.out ./...
	go tool cover -html=bin/coverage.out -o bin/coverage.html
	@echo "Coverage profile written to bin/coverage.html"

clean:
	rm -rf bin/

## help: Display this help message
help:
	@echo "Available make targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':'

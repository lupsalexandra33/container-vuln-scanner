BINARY  := vulnscan
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test test-v check fmt lint coverage clean help

## build: Compile the vulnscan binary into bin/
build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/vulnscan

## test: Run the test suite with the race detector
test:
	go test -race ./...

## test-v: Run the test suite with the race detector in verbose mode
test-v:
	go test -v -race ./...

## check: Format code, vet, and run tests
check: fmt
	go vet ./...
	go test -race ./...

## fmt: Format all Go source files with gofmt
fmt:
	gofmt -w .

## lint: Run golangci-lint if installed
lint:
	@if which golangci-lint > /dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed; skipping"; \
	fi

## coverage: Run tests with coverage and write an HTML profile to bin/coverage.html
coverage:
	@mkdir -p bin
	go test -race -coverprofile=bin/coverage.out ./...
	go tool cover -html=bin/coverage.out -o bin/coverage.html
	@echo "Coverage profile written to bin/coverage.html"

## clean: Remove build artifacts and coverage output from bin/
clean:
	rm -rf bin/

## help: Display this help message
help:
	@echo "Available make targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':'

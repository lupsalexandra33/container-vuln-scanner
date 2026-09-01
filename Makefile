BINARY  := vulnscan
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test check fmt clean

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/vulnscan

test:
	go test -race ./...

check: fmt
	go vet ./...
	go test -race ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin/

#!/bin/bash
set -e

echo "Building mock vulnerable image..."
docker build -t vulnscan-mock:latest ./testdata/mock-image

echo "Running vulnscan on the mock image..."
go run ./cmd/vulnscan scan vulnscan-mock:latest --out table

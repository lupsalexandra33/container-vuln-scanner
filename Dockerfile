FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.toolVersion=$VERSION" -o vulnscan ./cmd/vulnscan

FROM alpine:3.19

# Install dependencies required by the scanners (gcompat/libc6-compat for Go CGO binaries)
RUN apk add --no-cache curl bash docker-cli libc6-compat gcompat

# Install Syft (for SBOM generation)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install OSV-Scanner
RUN curl -sSfL -o /usr/local/bin/osv-scanner https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 && \
    chmod +x /usr/local/bin/osv-scanner

# Install Docker Scout CLI plugin
RUN curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s -- -b /usr/libexec/docker/cli-plugins

# Set up the cache strategy environment variables
ENV TRIVY_CACHE_DIR=/cache/trivy
ENV GRYPE_DB_CACHE_DIR=/cache/grype

# Create the cache directory
RUN mkdir -p /cache && chmod 777 /cache

# Copy the vulnscan binary and entrypoint
COPY --from=builder /app/vulnscan /usr/local/bin/vulnscan
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

#!/bin/bash
set -e

# Workaround for Docker Desktop credential helpers inside an Alpine container
if [ -f "/root/.docker/config.json" ]; then
    if grep -q "desktop.exe\|osxkeychain\|wincred" "/root/.docker/config.json"; then
        mkdir -p /tmp/.docker
        grep -v 'credsStore' /root/.docker/config.json > /tmp/.docker/config.json
        export DOCKER_CONFIG=/tmp/.docker
    fi
fi

# Authenticate Docker Scout if credentials are provided
if [ -n "$DOCKER_USER" ] && [ -n "$DOCKER_PAT" ]; then
    # Attempt login silently. If it fails, the orchestrator will catch it natively.
    echo "$DOCKER_PAT" | docker login -u "$DOCKER_USER" --password-stdin >/dev/null 2>&1 || true
fi

exec vulnscan "$@"

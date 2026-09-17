# Vulnerable Mock Image

This directory contains a standalone test suite used to generate a deliberately insecure container image (`vulnscan-mock:latest`). 

## Role & Purpose
The purpose of this mock image is to provide a reliable, locally buildable artifact that forcefully triggers all three security classifications supported by the orchestrator:
1. **Vulnerabilities (CVEs):** Triggered via outdated base packages.
2. **Misconfigurations:** Triggered via image metadata (Root User) and a highly insecure embedded Kubernetes manifest (`bad-deployment.yaml`).
3. **Secrets:** Triggered by injecting dummy, unencrypted AWS credentials into the final filesystem layer (`credentials`).

## Files
* `Dockerfile`: The instructions to build the insecure image. Copies the dummy files into the root filesystem.
* `credentials`: A file containing fake AWS keys to test the secret detection engine and redaction logic.
* `bad-deployment.yaml`: A file with severe security violations (e.g., `privileged: true`) to test the misconfiguration engine.
* `test-scan.sh`: A helper script that automatically builds the Docker image and immediately runs the `vulnscan` CLI against it.

## Usage

To build the image and run an end-to-end scan, simply execute the helper script:

```bash
./test-scan.sh
```


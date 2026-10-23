## Instructions: How to Build and Run

### 1. Build the Image
To build the self-contained scanner image locally:
```bash
docker build -t vulnscan:latest .
```

### 2. Run the Container
Because the container needs to orchestrate multiple tools, talk to external APIs, and cache databases, use the following command to run it perfectly:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v vulnscan-cache:/cache \
  -e DOCKER_USER=your_docker_username \
  -e DOCKER_PAT=your_personal_access_token \
  -e CLAIR_URL=http://host.docker.internal:6060 \
  vulnscan:latest scan debian:12
```

*(Note: If you want to use `--out tui` to view the interactive dashboard, you must add `-it` to your `docker run` command)*
```

### Explanation of the flags
* `-v /var/run/docker.sock:/var/run/docker.sock`: Allows the internal scanners to leverage your host's Docker engine to pull images.
* `-v vulnscan-cache:/cache`: Creates and mounts a persistent Docker Volume to store the Trivy and Grype databases so they aren't redownloaded.
* `-e DOCKER_USER` & `DOCKER_PAT`: Authenticates the `docker scout` CLI plugin securely without crashing the container on Docker Desktop credential helpers. (Optional: omit these if you don't need Scout).
* `-e CLAIR_URL`: Points the container to your external running Clair service.

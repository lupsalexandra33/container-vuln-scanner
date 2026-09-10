# Deployment Configuration

This directory contains the Docker Compose configurations for the external services required by the vulnerability scanner.

## Clair (Stage 3.1)

Clair operates as a service rather than a command-line tool. It requires a PostgreSQL database to store vulnerability data and image layer indexes.

### Running the Stack

```bash
cd deploy
docker-compose up -d
```

### Readiness Checks and First-Run Duration

When you start the Clair stack for the first time:
1. **Database Population**: Clair will immediately begin downloading vulnerability databases from multiple sources (Debian, Ubuntu, Alpine, etc.) into the PostgreSQL database.
2. **First-Run Duration**: Depending on your internet connection and CPU, this initial population can take anywhere from **5 to 15 minutes**.
3. **Readiness Check**: You can check if Clair is ready to accept scans by hitting its metrics/health API:
   ```bash
   curl -f http://localhost:6061/healthz
   ```
   The `docker-compose.yml` file includes a built-in healthcheck that runs this endpoint every 10 seconds.

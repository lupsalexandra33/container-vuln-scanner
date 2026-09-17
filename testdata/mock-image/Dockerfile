FROM alpine:latest

# 1. File-based Secrets
# Copying fake AWS credentials to trigger the secret scanner
RUN mkdir -p /root/.aws
COPY credentials /root/.aws/credentials

# 2. File-based Misconfigurations (IaC embedded in image)
# Copying a highly insecure Kubernetes Pod manifest to trigger the misconfig scanner
COPY bad-deployment.yaml /root/bad-deployment.yaml

CMD ["sh"]

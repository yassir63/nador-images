FROM python:3.11-slim

ARG KUBECTL_VERSION=v1.29.0

LABEL org.opencontainers.image.title="5G latency and throughput controller" \
      org.opencontainers.image.version="2026w45"

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl \
    && chmod +x /usr/local/bin/kubectl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir kopf kubernetes requests

COPY controller/k8scontroller.py common/tunnel_identity.py /app/
CMD ["python", "/app/k8scontroller.py"]

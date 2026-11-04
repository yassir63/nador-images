FROM python:3.10-slim

LABEL org.opencontainers.image.version="2026w43" \
      org.opencontainers.image.description="Multi-gNB tunnel mapping and PFCP session correlation; SMF/UPF F-SEIDs exposed by mapper. Test version."

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y tshark && \
    pip install pyshark redis && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY amf-sniffer/amf_sniffer.py /app/amf_sniffer.py

# Run as default user (optional: use root for full interface access if needed)
COPY common/tunnel_identity.py /app/tunnel_identity.py

CMD ["python", "/app/amf_sniffer.py"]

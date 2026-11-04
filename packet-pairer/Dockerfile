FROM python:3.11-slim

LABEL org.opencontainers.image.version="2026w43" \
      org.opencontainers.image.description="Multi-gNB tunnel mapping and PFCP session correlation; SMF/UPF F-SEIDs exposed by mapper. Test version."

WORKDIR /app

RUN pip install --no-cache-dir flask prometheus_client

COPY packet-pairer/same_packet_pairer.py /app/same_packet_pairer.py
COPY packet-pairer/entrypoint-same-packet-pairer.sh /app/entrypoint-same-packet-pairer.sh

RUN chmod +x /app/entrypoint-same-packet-pairer.sh

EXPOSE 9200 9201/udp

COPY common/tunnel_identity.py /app/tunnel_identity.py

CMD ["/app/entrypoint-same-packet-pairer.sh"]

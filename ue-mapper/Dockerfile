FROM python:3.10-slim

LABEL org.opencontainers.image.version="2026w45-ml" \
      org.opencontainers.image.description="Multi-gNB mapping and SMF/UPF F-SEID to IMSI metadata via inventory and Prometheus fiveg_ue_session_info. Test version."

RUN pip install flask redis prometheus-client

WORKDIR /app
COPY ue-mapper/ue_mapper_api.py /app/ue_mapper_api.py
COPY common/tunnel_identity.py /app/tunnel_identity.py
COPY ue-mapper/mapper_coverage.py /app/mapper_coverage.py

CMD ["python", "/app/ue_mapper_api.py"]

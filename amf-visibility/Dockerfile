FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 tshark util-linux iproute2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY amf-visibility/check.py /app/check.py
ENTRYPOINT ["python3", "/app/check.py"]

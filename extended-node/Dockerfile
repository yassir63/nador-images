FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-prometheus-client python3-requests python3-bpfcc \
    bpfcc-tools clang libbpf1 iproute2 util-linux tshark ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY extended-node/*.py /app/
COPY extended-node/nador_kernel/ /app/nador_kernel/
CMD ["python3", "/app/node_probe.py"]

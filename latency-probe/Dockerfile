FROM debian:bookworm-slim AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang gcc make linux-libc-dev libbpf-dev libelf-dev zlib1g-dev libjson-c-dev bpftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY latency-probe/gtp_latency.bpf.c latency-probe/gtp_latency.h \
     latency-probe/gtp_latency_user.c latency-probe/Makefile ./
RUN make BPFCFLAGS="-O2 -g -target bpf -I/usr/include/$(gcc -dumpmachine)"

FROM debian:bookworm-slim

LABEL org.opencontainers.image.version="2026w45" \
      org.opencontainers.image.description="Multi-gNB latency probe with PFCP session correlation and IPv4 fragmentation handling."

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-flask python3-prometheus-client \
        libbpf1 libelf1 zlib1g libjson-c5 iproute2 bash procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/gtp_latency_user ./
COPY latency-probe/exporter.py latency-probe/latency_socket_server.py \
     latency-probe/entrypoint-latency.sh ./
COPY common/tunnel_identity.py ./
RUN chmod +x entrypoint-latency.sh

EXPOSE 9100
CMD ["./entrypoint-latency.sh"]

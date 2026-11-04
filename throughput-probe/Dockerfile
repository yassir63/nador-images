FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang gcc make linux-libc-dev libbpf-dev libelf-dev zlib1g-dev bpftool && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY throughput-probe/gtp* throughput-probe/Makefile ./
RUN make

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-prometheus-client procps libbpf1 libelf1 zlib1g && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/gtp_throughput_user ./
COPY throughput-probe/exporter.py throughput-probe/entrypoint-throughput.sh ./
COPY common/tunnel_identity.py ./
RUN chmod +x entrypoint-throughput.sh
CMD ["./entrypoint-throughput.sh"]

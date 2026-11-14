FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang gcc linux-libc-dev libbpf-dev bpftool && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY n3-oneway/observer* ./
RUN clang -O2 -g -target bpf -I/usr/include/$(gcc -dumpmachine) -c observer.bpf.c -o observer.bpf.o \
    && bpftool gen skeleton observer.bpf.o > observer.skel.h \
    && gcc -O2 -Wall -Wextra -Werror observer.c -o nador-n3-observer -lbpf

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 util-linux libbpf1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /build/nador-n3-observer /usr/local/bin/
COPY n3-oneway/oneway.py n3-oneway/upf_transit.py n3-oneway/target_process.py ./
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/app/oneway.py"]

FROM rockylinux:9.3@sha256:d644d203142cd5b54ad2a83a203e1dee68af2229f8fe32f52a30c6e1d3c3a9e0

ARG LIBBPF_COMMIT=dd92bef7f6c7a00bb0312554119b6d9cf38e4f32
ARG BPFTOOL_COMMIT=12701baaac934e2f65a6deef890f8b0b7eae4edf
ARG KERNEL_VER=5.14.0-503.19.1.el9_5.x86_64

RUN dnf install -y bpftool kernel-devel git dos2unix python3 python3-pip clang llvm \
        elfutils-libelf-devel libcap-devel gcc glibc-devel glibc-devel.i686 \
        glibc-headers make perf nano iproute-tc jq \
    && dnf install -y 'dnf-command(config-manager)' \
    && dnf config-manager --set-enabled devel \
    && dnf install -y libbpf-devel json-c json-c-devel \
    && dnf clean all

RUN curl -fL --retry 3 -o /tmp/kernel-headers.rpm \
        https://dl.rockylinux.org/vault/rocky/9.5/devel/x86_64/os/Packages/k/kernel-headers-${KERNEL_VER}.rpm \
    && curl -fL --retry 3 -o /tmp/kernel-devel.rpm \
        https://dl.rockylinux.org/vault/rocky/9.5/devel/x86_64/os/Packages/k/kernel-devel-${KERNEL_VER}.rpm \
    && echo '8f1948a1a5de7e7a5db551dfce1881a1888750a212a286159c707ff7d8962363  /tmp/kernel-headers.rpm' | sha256sum -c - \
    && echo '70b340811bf68e3a826f7ed898b310c1d98917ff9df35456e65874582afdae81  /tmp/kernel-devel.rpm' | sha256sum -c - \
    && dnf install -y /tmp/kernel-headers.rpm /tmp/kernel-devel.rpm \
    && rm /tmp/kernel-headers.rpm /tmp/kernel-devel.rpm

WORKDIR /app
COPY latency-probe-rocky/requirements.txt ./
RUN python3 -m pip install --no-cache-dir -r requirements.txt && python3 -m pip check

RUN curl -fL -o /tmp/crictl.tar.gz \
        https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.28.0/crictl-v1.28.0-linux-amd64.tar.gz \
    && tar -xzf /tmp/crictl.tar.gz -C /usr/local/bin \
    && chmod +x /usr/local/bin/crictl && rm /tmp/crictl.tar.gz

RUN git init libbpf && cd libbpf \
    && git remote add origin https://github.com/libbpf/libbpf.git \
    && git fetch --depth 1 origin "${LIBBPF_COMMIT}" && git checkout --detach FETCH_HEAD \
    && make -C src install
RUN git init bpftool && cd bpftool \
    && git remote add origin https://github.com/libbpf/bpftool.git \
    && git fetch --depth 1 origin "${BPFTOOL_COMMIT}" && git checkout --detach FETCH_HEAD \
    && git submodule update --init --recursive \
    && test "$(git -C libbpf rev-parse HEAD)" = "${LIBBPF_COMMIT}" \
    && make -C src install

COPY latency-probe-rocky/Makefile latency-probe-rocky/gtp_latency.bpf.c \
     latency-probe-rocky/gtp_latency.h latency-probe-rocky/gtp_latency_user.c \
     latency-probe-rocky/exporter.py latency-probe-rocky/latency_socket_server.py \
     latency-probe-rocky/entrypoint-latency.sh ./
COPY common/tunnel_identity.py ./
# The original build generated vmlinux.h, but these sources never include it.
RUN dos2unix Makefile && make -B && chmod +x entrypoint-latency.sh

EXPOSE 9100
CMD ["./entrypoint-latency.sh"]

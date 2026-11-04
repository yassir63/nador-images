CLANG ?= clang
CC ?= gcc
ARCH_INCLUDE = /usr/include/$(shell $(CC) -dumpmachine)
all: gtp_throughput_user
gtp_throughput.bpf.o: gtp_throughput.bpf.c gtp_packet.h
	$(CLANG) -O2 -g -target bpf -I$(ARCH_INCLUDE) -c $< -o $@
gtp_throughput.skel.h: gtp_throughput.bpf.o
	bpftool gen skeleton $< > $@
gtp_throughput_user: gtp_throughput_user.c gtp_throughput.skel.h
	$(CC) -O2 -Wall -Wextra $< -o $@ -lbpf -lelf -lz
clean:
	rm -f gtp_throughput.bpf.o gtp_throughput.skel.h gtp_throughput_user

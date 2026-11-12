# Makefile for GTP latency eBPF program

BPF_C = gtp_latency.bpf.c
BPF_O = gtp_latency.bpf.o
SKEL_H = gtp_latency.skel.h
USER_C = gtp_latency_user.c
USER_BIN = gtp_latency_user
IFACE ?= n2
PRIO ?= 1
HANDLE ?= 1 

CLANG = clang
BPFCFLAGS = -O2 -g -target bpf
USERCFLAGS = -O2 -g

INCLUDES = -I. -I./include -I/usr/include/bpf

.PHONY: all clean run attach detach

all: $(USER_BIN)

# Compile eBPF object
$(BPF_O): $(BPF_C) gtp_latency.h
	@echo ">> Compiling eBPF object"
	$(CLANG) $(BPFCFLAGS) -c $< -o $@

# Generate skeleton header
$(SKEL_H): $(BPF_O)
	@echo ">> Generating BPF skeleton header"
	bpftool gen skeleton $< > $@

# Compile user-space program
$(USER_BIN): $(USER_C) $(SKEL_H) gtp_latency.h tcp_repeat.h tcp_rtt_variation.h
	@echo ">> Compiling user-space program"
	gcc $(USERCFLAGS) $(INCLUDES) -o $@ $(USER_C) -lelf -lz -lbpf -ljson-c

# Build and run the program
# run: all
# 	@echo ">> Ensuring clsact qdisc is installed on $(IFACE)"
# 	@tc qdisc show dev $(IFACE) | grep -q clsact || tc qdisc add dev $(IFACE) clsact
# 	@echo ">> Running user-space program on interface $(IFACE) with Handle = $(HANDLE) and Priority = $(PRIO) with TEIDs: $(TEIDS)"
# 	./$(USER_BIN) $(IFACE) --prio $(PRIO) --handle $(HANDLE) $(TEIDS)

run: all
	@echo ">> Ensuring clsact qdisc is installed on $(IFACE)"
	@tc qdisc show dev $(IFACE) | grep -q clsact || tc qdisc add dev $(IFACE) clsact
	@echo ">> Running user-space program with:"
	@echo "   Interface: $(IFACE)"
	@echo "   Handle:    $(HANDLE)"
	@echo "   Priority:  $(PRIO)"
	@echo "   TEIDs:     $(TEIDS)"
#	exec ./$(USER_BIN) $(IFACE) --prio $(PRIO) --handle $(HANDLE) $(TEIDS)


# Clean up filters and qdisc
detach:
	@echo ">> Detaching BPF programs and removing qdisc from $(IFACE)"
	@tc qdisc del dev $(IFACE) clsact 2>/dev/null || true

# Cleanup build artifacts
clean:
	@echo ">> Cleaning up"
	rm -f $(USER_BIN) $(BPF_O) $(SKEL_H)




# exec ./$(USER_BIN) $(IFACE) --prio $(PRIO) --handle $(HANDLE) $${teid_array[@]}

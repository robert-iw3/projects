# Makefile for eBPF CO-RE C2 Probe v2.7

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# -g is required to generate BTF debug info
# -O2 is required by the BPF compiler backend
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# Standard libbpf include paths for Ubuntu
INCLUDES := -I/usr/include/bpf -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: all clean

all: vmlinux.h c2_probe.bpf.o

# Generate vmlinux.h directly from the running kernel
vmlinux.h:
	@echo "Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

c2_probe.bpf.o: c2_probe.bpf.c vmlinux.h
	@echo "Compiling eBPF probe for v2.7..."
	$(CLANG) $(CFLAGS) $(INCLUDES) -c c2_probe.bpf.c -o c2_probe.bpf.o

clean:
	@echo "Cleaning up build artifacts..."
	rm -f c2_probe.bpf.o vmlinux.h
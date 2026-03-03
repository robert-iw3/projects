# ==============================================================================
# Makefile for C2 Beacon Hunter eBPF Probes (v2.8)
# ==============================================================================

APP = c2_loader
BPF_OBJ = c2_probe.bpf.o
SKEL = c2_probe.skel.h

# Compilers & Tools
CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

# Architectures
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Flags
CFLAGS = -g -O2 -Wall
LDFLAGS = -lbpf -lelf -lz

all: $(APP)

# Step 1: Compile the eBPF C code into an ELF object file using Clang
$(BPF_OBJ): c2_probe.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I . -c $< -o $@

# Step 2: Use bpftool to generate the C skeleton header from the ELF object
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Step 3: Compile the user-space loader, linking against libbpf and the skeleton
$(APP): c2_loader.c $(SKEL)
	$(CC) $(CFLAGS) -I . $< -o $@ $(LDFLAGS)

clean:
	rm -f $(APP) $(BPF_OBJ) $(SKEL)
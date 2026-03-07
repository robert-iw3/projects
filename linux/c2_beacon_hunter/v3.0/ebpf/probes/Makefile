CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

all: c2_promisc_loader

c2_promisc.bpf.o: c2_promisc.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $< -o $@

c2_promisc.skel.h: c2_promisc.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

c2_promisc_loader: c2_promisc_loader.c c2_promisc.skel.h
	$(CC) -g -O2 -Wall c2_promisc_loader.c -lbpf -o $@

clean:
	rm -f *.o *.skel.h c2_promisc_loader
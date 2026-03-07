// v3.0/c2_promisc_loader.c — Robust loader with full error handling
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "c2_promisc.skel.h"

static struct c2_promisc_bpf *skel = NULL;
static volatile int exiting = 0;

static void sig_handler(int sig) {
    exiting = 1;
}

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *iface = argc > 1 ? argv[1] : "wlo1";
    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    printf("[PROMISC-LOADER v3.0] Starting on %s (IPv4+IPv6)\n", iface);

    skel = c2_promisc_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[ERROR] Failed to open/load skeleton\n");
        return 1;
    }

    // Detach any old program
    bpf_xdp_detach(ifindex, 0, NULL);

    int fd = bpf_program__fd(skel->progs.xdp_c2_promisc);
    if (fd < 0) {
        fprintf(stderr, "[ERROR] No XDP program FD\n");
        goto cleanup;
    }

    if (bpf_xdp_attach(ifindex, fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "[ERROR] Failed to attach XDP (try XDP_FLAGS_SKB_MODE)\n");
        goto cleanup;
    }

    printf("[SUCCESS] Promiscuous parser attached (IPv4 + IPv6)\n");
    printf("[READY] Ringbuf events flowing to Python collector\n");

    while (!exiting) {
        sleep(1);
    }

    printf("[SHUTDOWN] Detaching program...\n");
    bpf_xdp_detach(ifindex, 0, NULL);

cleanup:
    c2_promisc_bpf__destroy(skel);
    return 0;
}
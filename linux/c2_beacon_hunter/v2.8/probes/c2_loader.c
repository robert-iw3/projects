#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>       // Required for if_nametoindex
#include <bpf/libbpf.h>
#include "c2_probe.skel.h"

struct event_t {
    uint32_t pid;
    uint32_t type;
    uint32_t dst_ip;
    uint16_t dst_port;
    char comm[16];
    char dns_query[64];
    uint32_t payload_entropy;
};

// Callback triggered every time the kernel writes to the Ring Buffer
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;

    // Convert 32-bit network IP to readable string
    struct in_addr ip_addr;
    ip_addr.s_addr = e->dst_ip;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_addr, ip_str, INET_ADDRSTRLEN);

    // Serialize to JSON for Python pipeline ingestion
    if (e->type == 1) { // UDP_DNS
        printf("{\"type\": \"dns\", \"pid\": %u, \"comm\": \"%s\", \"dst_ip\": \"%s\", \"dst_port\": %u, \"dns_query\": \"%s\"}\n",
               e->pid, e->comm, ip_str, e->dst_port, e->dns_query);
    }
    else if (e->type == 2) { // TCP_ENTROPY
        double entropy = e->payload_entropy / 100.0;
        printf("{\"type\": \"tcp_payload\", \"pid\": %u, \"comm\": \"%s\", \"dst_ip\": \"%s\", \"dst_port\": %u, \"entropy\": %.2f}\n",
               e->pid, e->comm, ip_str, e->dst_port, entropy);
    }

    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    struct c2_probe_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // Default to eth0 if no interface is provided
    const char *iface = (argc > 1) ? argv[1] : "eth0";

    // Convert the interface name string (e.g., "eth0") to a kernel interface index
    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "[-] Failed to resolve interface %s. Does it exist?\n", iface);
        return 1;
    }

    // 1. Open and load the BPF skeleton into the kernel
    skel = c2_probe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 2. Attach the standard kprobes (tcp_v4_connect, tcp_sendmsg, udp_sendmsg)
    // Note: libbpf automatically skips attaching SEC("xdp") during this call
    // because XDP programs require an explicit ifindex context.
    err = c2_probe_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to attach BPF kprobes\n");
        goto cleanup;
    }

    // 3. Manually attach the XDP program to the targeted network interface
    skel->links.xdp_drop_malicious = bpf_program__attach_xdp(skel->progs.xdp_drop_malicious, ifindex);
    if (!skel->links.xdp_drop_malicious) {
        fprintf(stderr, "[-] Failed to attach XDP program to interface %s\n", iface);
        err = -1;
        goto cleanup;
    }

    // 4. Set up ring buffer polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "[-] Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("{\"status\": \"C-Loader initialized. Attached XDP to %s. Native tracing active.\"}\n", iface);
    fflush(stdout);

    // Enter high-speed polling loop
    while (1) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "[-] Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    c2_probe_bpf__destroy(skel); // This automatically detaches the XDP link and kprobes
    return -err;
}
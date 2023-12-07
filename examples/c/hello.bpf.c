#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// This global variable it's converted to a MAP
int counter = 0;

// SEC() is a macro that defines the type of eBPF program
SEC("xdp")
int hello(struct xdp_md *ctx) {
    // bpf_printk is a helper function by libbpf
    bpf_printk("Packet received %d", counter);
    counter++;
    // XDP functions return the action for the packet
    return XDP_PASS;
}

// The eBPF verifier inspects the license of eBPF programs
char LICENSE[] SEC("license") = "Dual BSD/GPL";

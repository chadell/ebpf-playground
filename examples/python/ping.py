#!/usr/bin/python3
from bcc import BPF

program = r"""
#include "network.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

int xdp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (is_icmp_ping_request(data, data_end)) {
        bpf_trace_printk("Got an ICMP packet");
        // play with XDP_DROP
        return XDP_PASS;
  }

  return XDP_PASS;
}
"""

# Loads the C code from a string
b = BPF(text=program)

# Load the function into XDP
fx = b.load_func("xdp", BPF.XDP)

# XDP will be the first program hit when a packet is received ingress
BPF.attach_xdp("lo", fx, 0)

# Outputs the trace in the screen
b.trace_print()

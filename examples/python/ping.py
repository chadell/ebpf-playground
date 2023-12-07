#!/usr/bin/python3
from bcc import BPF
import socket
import os
from time import sleep

program = r"""
#include "network.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

int xdp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (is_icmp_ping_request(data, data_end)) {
        bpf_trace_printk("Got ping packet");
        # play with XDP_DROP
        return XDP_PASS;
  }

  return XDP_PASS;
}
"""

interface = "lo" #2
b = BPF(text=program) #3
fx = b.load_func("xdp", BPF.XDP) #4
# XDP will be the first program hit when a packet is received ingress
BPF.attach_xdp(interface, fx, 0)

b.trace_print()

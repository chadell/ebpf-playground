#!/usr/bin/python3
from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello NetBCN!");
    return 0;
}
"""

# Loads the C code from a string
b = BPF(text=program)

# Retrieves the syscall for execve
syscall = b.get_syscall_fnname("execve")

# Attaches the C function hello to the event
b.attach_kprobe(event=syscall, fn_name="hello")

# Outputs the trace in the screen
b.trace_print()

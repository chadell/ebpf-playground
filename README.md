# ebpf-playground


# C example

- Install libbpf/src

root@ebpf-lab-1:/tmp# git clone git@github.com:libbpf/libbpf.git
root@ebpf-lab-1:/tmp# cd libbpf/
root@ebpf-lab-1:/tmp/libbpf# git reset --hard a6d7530cb7dff87ac1e64a540e63b67ddde2e0f9
HEAD is now at a6d7530 Makefile: bump version to v1.0.1
root@ebpf-lab-1:/tmp/libbpf# cd src/
root@ebpf-lab-1:/tmp/libbpf/src# make install


- Complile program
clang -target bpf -I /usr/include/x86_64-linux-gnu -g -O2 -o hello.bpf.o -c hello.bpf.c

root@ebpf-lab-1:~/ebpf-playground/examples/c# file hello.bpf.o
hello.bpf.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), with debug_info, not stripped

root@ebpf-lab-1:~/ebpf-playground/examples/c# llvm-objdump -S hello.bpf.o

hello.bpf.o:    file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <hello>:
;     bpf_printk("Packet received %d", counter);
       0:       18 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r6 = 0 ll
       2:       61 63 00 00 00 00 00 00 r3 = *(u32 *)(r6 + 0)
       3:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0 ll
       5:       b7 02 00 00 0f 00 00 00 r2 = 15
       6:       85 00 00 00 06 00 00 00 call 6
;     counter++;
       7:       61 61 00 00 00 00 00 00 r1 = *(u32 *)(r6 + 0)
       8:       07 01 00 00 01 00 00 00 r1 += 1
       9:       63 16 00 00 00 00 00 00 *(u32 *)(r6 + 0) = r1
;     return XDP_PASS;
      10:       b7 00 00 00 02 00 00 00 r0 = 2
      11:       95 00 00 00 00 00 00 00 exit



- Install bpftool

https://github.com/libbpf/bpftool/releases

git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make install


root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool prog load hello.bpf.o /sys/fs/bpf/hello

root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool prog list
...
147: xdp  name hello  tag d35b94b4c0c10efb  gpl
        loaded_at 2023-12-07T13:39:08+0000  uid 0
        xlated 96B  jited 64B  memlock 4096B  map_ids 3,4
        btf_id 64


root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool prog show id 147 --pretty
{
    "id": 147,
    "type": "xdp",
    "name": "hello",
    "tag": "d35b94b4c0c10efb",
    "gpl_compatible": true,
    "loaded_at": 1701956348,
    "uid": 0,
    "bytes_xlated": 96,
    "jited": true,
    "bytes_jited": 64,
    "bytes_memlock": 4096,
    "map_ids": [3,4
    ],
    "btf_id": 64
}

root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool net list
xdp:
lo(1) generic id 147

tc:

flow_dissector:

netfilter:

root@ebpf-lab-1:~/ebpf-playground/examples/c# ip link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 xdpgeneric qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    prog/xdp id 147 tag d35b94b4c0c10efb jited


root@ebpf-lab-1:~/ebpf-playground/examples/c# cat /sys/kernel/debug/tracing/trace_pipe
            sshd-13707   [000] d.s11  7517.712510: bpf_trace_printk: Packet Received 2222
            ...

root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool map list
3: array  name hello.bss  flags 0x400
        key 4B  value 4B  max_entries 1  memlock 4096B
        btf_id 64
4: array  name hello.rodata  flags 0x80
        key 4B  value 15B  max_entries 1  memlock 4096B
        btf_id 64  frozen
16: array  name pid_iter.rodata  flags 0x480
        key 4B  value 4B  max_entries 1  memlock 4096B
        btf_id 82  frozen
        pids bpftool(17487)
17: array  name libbpf_det_bind  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B

root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool map dump name hello.rodata
[{
        "value": {
            ".rodata": [{
                    "hello.____fmt": "Packet Received %d"
                }
            ]
        }
    }
]

- Detaching the program
root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool net detach xdp dev lo

- Unload the Program
root@ebpf-lab-1:~/ebpf-playground/examples/c# rm /sys/fs/bpf/hello
root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool prog show name hello

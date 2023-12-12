# ebpf-playground

Slides available at [ebpf101.pdf](ebpf101.pdf).

## Lab environment

There is a Terraform plan ready to deploy in Digital Ocean within the `lab` folder.

```bash
$ cd lab/
$ terraform init
$ terraform apply

```

It installs an Ubuntu server 22.04, with some extra packages to allow compiling C code, BFP helpers, etc. You can check them in `lab/servers.tf`.

## BCC hello.py example

This program simply attaches to the `execvd()` syscall and outputs a string.

### Install BCC library

Instructions: https://github.com/iovisor/bcc

```bash
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
```

### Run it

```py
root@ebpf-lab-1:~/ebpf-playground/examples/python# python3 hello.py
... some warnings ...

b'           <...>-56207   [001] d...1 83066.403493: bpf_trace_printk: Hello NetBCN!'
b'              sh-56208   [001] d...1 83066.405217: bpf_trace_printk: Hello NetBCN!'
b'            node-56209   [001] d...1 83066.408074: bpf_trace_printk: Hello NetBCN!'
```

> Stop it with ctrl+C

Here, as soon as the eBPF program is loaded, you get every executable that uses the `execvd()` syscall.

Aside from the `Hello NetBCN!` string, you get also context info for the process ID, and the command running. For instance, process ID 56208 and command `sh`.

## BCC ping.py example

This program is attached to the XDP hook in the loopback interface `lo`, and counts the packets received.

### Run it

In the terminal, start the `ping.py`:

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/python# python3 ping.py
... some warnings ...
```

At this point, nothing happens, because no packets are directed to the loopback.

In a second terminal, you ping the loopback IP address:

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/python# ping 127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.050 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.044 ms
^C
--- 127.0.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1005ms
rtt min/avg/max/mdev = 0.044/0.047/0.050/0.003 ms
```

If you check the first terminal you will notice the packets received.

```bash
b'            ping-56396   [001] d.s11 83468.169646: bpf_trace_printk: Got ping packet'
b'            ping-56396   [001] d.s11 83469.174448: bpf_trace_printk: Got ping packet'
```

As an experiment, you can change the XDP code in the `ping.py`, from `XDP_PASS` to XDP_DROP.

```c
  if (is_icmp_ping_request(data, data_end)) {
        bpf_trace_printk("Got an ICMP packet");
        return XDP_DROP;
  }
```

Now, if you repeat the test, you will see how the ICMP packets are not returned (because are dropped):

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/python# ping 127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
^C
--- 127.0.0.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2036ms

```

## C example

### Install `libbpf`

```bash

root@ebpf-lab-1:/tmp# git clone git@github.com:libbpf/libbpf.git
root@ebpf-lab-1:/tmp# cd libbpf/
root@ebpf-lab-1:/tmp/libbpf# git reset --hard a6d7530cb7dff87ac1e64a540e63b67ddde2e0f9
HEAD is now at a6d7530 Makefile: bump version to v1.0.1
root@ebpf-lab-1:/tmp/libbpf# cd src/
root@ebpf-lab-1:/tmp/libbpf/src# make install
```

### Compile program

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/c# clang -target bpf -I /usr/include/x86_64-linux-gnu -g -O2 -o hello.bpf.o -c hello.bpf.c

```

### Check the compiled object

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/c# file hello.bpf.o
hello.bpf.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), with debug_info, not stripped
```

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/c# llvm-objdump -S hello.bpf.o

hello.bpf.o: file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <hello>:
; bpf*printk("Packet received %d", counter);
0: 18 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r6 = 0 ll
2: 61 63 00 00 00 00 00 00 r3 = *(u32 _)(r6 + 0)
3: 18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0 ll
5: b7 02 00 00 0f 00 00 00 r2 = 15
6: 85 00 00 00 06 00 00 00 call 6
; counter++;
7: 61 61 00 00 00 00 00 00 r1 = _(u32 _)(r6 + 0)
8: 07 01 00 00 01 00 00 00 r1 += 1
9: 63 16 00 00 00 00 00 00 _(u32 \_)(r6 + 0) = r1
; return XDP_PASS;
10: b7 00 00 00 02 00 00 00 r0 = 2
11: 95 00 00 00 00 00 00 00 exit
```

## Meet your BPF friend: `bpftool`

### Install bpftool

```bash
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make install
```

## Load the eBPF code

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool prog load hello.bpf.o /sys/fs/bpf/hello
root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool prog list
...
147: xdp name hello tag d35b94b4c0c10efb gpl
loaded_at 2023-12-07T13:39:08+0000 uid 0
xlated 96B jited 64B memlock 4096B map_ids 3,4
btf_id 64
```

### Check the XDP program loaded

```bash
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
```

### Attach to the loopback

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool net attach xdp id 147 dev lo
```

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool net list
xdp:
lo(1) generic id 147

tc:

flow_dissector:

netfilter:
```

```bash


root@ebpf-lab-1:~/ebpf-playground/examples/c# ip link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 xdpgeneric qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
prog/xdp id 147 tag d35b94b4c0c10efb jited
...
```

### Check what's going on

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/c# cat /sys/kernel/debug/tracing/trace_pipe
sshd-13707 [000] d.s11 7517.712510: bpf_trace_printk: Packet Received 2222
...
```

### BFP Maps

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool map list
3: array name hello.bss flags 0x400
key 4B value 4B max_entries 1 memlock 4096B
btf_id 64
4: array name hello.rodata flags 0x80
key 4B value 15B max_entries 1 memlock 4096B
btf_id 64 frozen
16: array name pid_iter.rodata flags 0x480
key 4B value 4B max_entries 1 memlock 4096B
btf_id 82 frozen
pids bpftool(17487)
17: array name libbpf_det_bind flags 0x0
key 4B value 32B max_entries 1 memlock 4096B
```

```json
root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool map dump name hello.bss
[{
        "value": {
            ".bss": [{
                    "counter": 703
                }
            ]
        }
    }
]
```

### Detaching the program

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool net detach xdp dev lo
```

### Unload the program

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/c# rm /sys/fs/bpf/hello
root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool prog show name hello
```

### Let's try to make the Verifier unhappy

Comment out the LICENSE, compile again, and try to load the eBPF

```bash
root@ebpf-lab-1:~/ebpf-playground/examples/c# bpftool prog load hello.bpf.o /sys/fs/bpf/hello
libbpf: prog 'hello': BPF program load failed: Invalid argument
libbpf: prog 'hello': -- BEGIN PROG LOAD LOG --
; bpf_printk("Packet received %d", counter);
0: (18) r6 = 0xffff948300218000
2: (61) r3 = *(u32 *)(r6 +0)
 R1=ctx(id=0,off=0,imm=0) R6_w=map_value(id=0,off=0,ks=4,vs=4,imm=0) R10=fp0
3: (18) r1 = 0xffff88d7340bdd10
5: (b7) r2 = 19
6: (85) call bpf_trace_printk#6
cannot call GPL-restricted function from non-GPL compatible program
processed 5 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'hello': failed to load: -22
libbpf: failed to load object 'hello.bpf.o'
Error: failed to load object file
```

## References

https://github.com/lizrice/learning-ebpf
https://prathyushpv.github.io/2019/05/20/Building_usefull_tools_with_eBPF_Part1_Setting_up_bcc.html
https://gist.github.com/satrobit/17eb0ddd4e122425d96f60f45def9627
https://speakerdeck.com/fedepaol/ebpf-for-the-rest-of-us-golab-2023?slide=120

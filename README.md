# ebpf-playground


# C example

- Install libbpf/src

root@ebpf-lab-1:/tmp# git clone git@github.com:libbpf/libbpf.git

- Install `clang` compliler


clang  -target bpf -I/usr/include/$(shell uname -m)-linux-gnu -g -O2 -o $@ -c hello.bpf.c


- Install bpftool

https://github.com/libbpf/bpftool/releases

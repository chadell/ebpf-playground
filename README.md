# ebpf-playground


# C example

- Install libbpf/src

root@ebpf-lab-1:/tmp# git clone git@github.com:libbpf/libbpf.git
root@ebpf-lab-1:/tmp# cd libbpf/
root@ebpf-lab-1:/tmp/libbpf# git reset --hard a6d7530cb7dff87ac1e64a540e63b67ddde2e0f9

- Install `clang` compliler


clang  -target bpf -I/usr/include/$(shell uname -m)-linux-gnu -g -O2 -o $@ -c hello.bpf.c


- Install bpftool

https://github.com/libbpf/bpftool/releases

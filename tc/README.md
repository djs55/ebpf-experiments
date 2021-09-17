# Example Traffic Classifier (TC) program

tc-example.c from https://docs.cilium.io/en/latest/bpf/

Easy build instructions:
```
cd bpf
docker build --output type=local,dest=build .

Low-level build instructions:
```
mkdir bpf/build
clang -O2 -Wall -target bpf -c bpf/tc-example.c -o bpf/build/tc-example.o
```

Install:
```
docker run -it --privileged -v $(pwd):/test -w /test alpine sh
apk add iproute2-tc

mount none /sys/fs/bpf -t bpf

tc qdisc add dev eth0 clsact

tc filter add dev eth0 ingress bpf da obj tc/bpf/build/tc-example.o sec ingress

tc filter add dev eth0 egress bpf da obj tc/bpf/build/tc-example.o sec egress
```

Query:
```
go build
./tc
```

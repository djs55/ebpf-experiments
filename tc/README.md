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
tc qdisc add dev eno1 clsact

tc filter add dev eno1 ingress bpf da obj bpf/build/tc-example.o sec ingress

tc filter add dev eno1 egress bpf da obj bpf/build/tc-example.o sec egress
```

Query:
```
go build
./tc
```

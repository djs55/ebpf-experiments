# Example Traffic Classifier (TC) program

tc-example.c from https://docs.cilium.io/en/latest/bpf/

```
clang -O2 -Wall -target bpf -c bpf/tc-example.c -o bpf/tc-example.o

tc qdisc add dev eno1 clsact

tc filter add dev eno1 ingress bpf da obj bpf/tc-example.o sec ingress

tc filter add dev eno1 egress bpf da obj bpf/tc-example.o sec egress

go build
./tc
```

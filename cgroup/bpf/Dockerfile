FROM alpine AS build

# Dependencies needed to build BPF
RUN apk add alpine-sdk linux-headers clang clang-dev libbpf libbpf-dev iproute2

COPY bpf.c .
COPY bpf_helpers.h .
RUN clang -O2 -Wall -target bpf -c bpf.c -o bpf.o

FROM scratch
COPY --from=build bpf.o .

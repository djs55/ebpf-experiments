FROM alpine AS build

# Dependencies needed to build BPF
RUN apk add alpine-sdk linux-headers clang clang-dev libbpf libbpf-dev iproute2

COPY tc-example.c .
RUN clang -O2 -Wall -target bpf -c tc-example.c -o tc-example.o

FROM scratch
COPY --from=build tc-example.o .
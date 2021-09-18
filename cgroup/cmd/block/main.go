package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage:")
		fmt.Printf("%s <IP>\n", os.Args[0])
		fmt.Println("   -- add <IP> to the blocklist")
		os.Exit(1)
	}
	ip := binary.LittleEndian.Uint32(net.ParseIP(os.Args[1]))
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/blocked_map", &ebpf.LoadPinOptions{})
	if err != nil {
		panic(err)
	}
	if err := m.Put(&ip, &ip); err != nil {
		panic(err)
	}
}

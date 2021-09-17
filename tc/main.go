package main

import (
	"fmt"
	"path"

	"github.com/cilium/ebpf"
)

const (
	rootCgroup = "/sys/fs/cgroup/unified"
	ebpfFS     = "/sys/fs/bpf"
	accMapName = "acc_map"
)

func main() {
	m, err := ebpf.LoadPinnedMap(path.Join(ebpfFS, "tc", "globals", "acc_map"), &ebpf.LoadPinOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Opened pinned map\n")
	fmt.Printf("map KeySize    = %d\n", m.KeySize())
	fmt.Printf("map ValueSize  = %d\n", m.ValueSize())
	fmt.Printf("map MaxEntries = %d\n", m.MaxEntries())
	var in, out uint32
	if err := m.Lookup(uint32(0), &in); err != nil {
		panic(err)
	}
	if err := m.Lookup(uint32(1), &out); err != nil {
		panic(err)
	}
	fmt.Printf("in: %d, out: %d\n", in, out)
}

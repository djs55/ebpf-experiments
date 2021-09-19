package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var (
	// Paths to pin objects in /sys/fs/bpf:
	blockedMapPath = "/sys/fs/bpf/blocked_map"

	// Symbols from bpf.c:
	ingressProgram = "ingress"
	egressProgram  = "egress"
	blockedMap     = "blocked_map"
	flowsMap       = "flows_map"
)

func main() {
	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "cgroup to attach ingress/egress hooks to")
	bpf := flag.String("bpf", "bpf/bpf.o", "path to compiled eBPF code")
	flag.Parse()

	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})

	c, err := ebpf.LoadCollection(*bpf)
	if err != nil {
		panic(err)
	}

	// The links to the cgroup will be removed when the program exits.
	if _, err = link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroup,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: c.Programs[ingressProgram],
	}); err != nil {
		panic(err)
	}
	if _, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroup,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: c.Programs[egressProgram],
	}); err != nil {
		panic(err)
	}

	// A separate program needs to access the shared map so pin it to the fs.
	if err := os.Remove(blockedMapPath); err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	if err := c.Maps[blockedMap].Pin(blockedMapPath); err != nil {
		panic(err)
	}

	/* The link to the cgroup is not pinned so will be disconnected
	   when the program exits and the refcounts decrease. */
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("eBPF loaded and active. Hit Control+C to unload and exit.")
	// Display recent decisions for debugging:
	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-ticker.C:
			var conn conn
			for c.Maps[flowsMap].LookupAndDelete(nil, &conn) == nil {
				fmt.Println(unmarshalFlow(conn))
			}
		case <-sigc:
			return
		}
	}

}

// Matches definition in bpf.c
type conn struct {
	Flags uint32
	Dst   uint32
	Src   uint32
}

// Higher-level Go version
type flow struct {
	Blocked bool
	Egress  bool
	Src     net.IP
	Dst     net.IP
}

func (f flow) String() string {
	return fmt.Sprintf("{ Src = %s, Dst = %s, Egress = %v, Blocked = %v }", f.Src, f.Dst, f.Egress, f.Blocked)
}

func unmarshalFlow(c conn) flow {
	return flow{
		Blocked: c.Flags&2 != 0,
		Egress:  c.Flags&1 != 0,
		Src:     unmarshalIPv4(c.Src),
		Dst:     unmarshalIPv4(c.Dst),
	}
}

func unmarshalIPv4(ipv4 uint32) net.IP {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], ipv4)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

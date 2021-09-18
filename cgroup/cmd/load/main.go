package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
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

	cg, err := os.Open(*cgroup)
	if err != nil {
		panic(err)
	}

	fmt.Printf("attaching ingress to cgroup %s\n", cg.Name())
	if _, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cg.Name(),
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: c.Programs["ingress"],
	}); err != nil {
		panic(err)
	}
	fmt.Printf("attaching egress to cgroup %s\n", cg.Name())
	if _, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cg.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: c.Programs["egress"],
	}); err != nil {
		panic(err)
	}

	/* None of the resources are explicitly pinned so will be unloaded
	   when the program exits and the refcounts decrease. */
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("eBPF loaded and active. Hit Control+C to unload and exit.")
	<-sigc
}

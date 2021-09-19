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

var (
	// Paths to pin objects in /sys/fs/bpf:
	ingressProgramPath    = "/sys/fs/bpf/ingress_program"
	ingressCgroupLinkPath = "/sys/fs/bpf/ingress_cgroup_link"
	egressProgramPath     = "/sys/fs/bpf/egress_program"
	egressCgroupLinkPath  = "/sys/fs/bpf/egress_cgroup_link"
	blockedMapPath        = "/sys/fs/bpf/blocked_map"

	// Symbols from bpf.c
	ingressProgram = "ingress"
	egressProgram  = "egress"
	blockedMap     = "blocked_map"
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

	if err := c.Programs[ingressProgram].Pin(ingressProgramPath); err != nil{
		panic(err)
	}
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroup,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: c.Programs[ingressProgram],
	})
	if err != nil {
		panic(err)
	}
	if err := l.Pin(ingressCgroupLinkPath); err != nil {
		panic(err)
	}

	if err := c.Programs[egressProgram].Pin(egressProgramPath); err != nil{
		panic(err)
	}
	l, err = link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroup,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: c.Programs[egressProgram],
	})
	if err != nil {
		panic(err)
	}
	if err := l.Pin(egressCgroupLinkPath); err != nil {
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
	<-sigc

	if err := os.Remove(ingressProgramPath); err != nil {
		fmt.Printf("removing %s: %v\n", ingressProgramPath, err)
	}
	if err := os.Remove(egressProgramPath); err != nil {
		fmt.Printf("removing %s: %v\n", egressProgramPath, err)
	}
	if err := os.Remove(ingressCgroupLinkPath); err != nil {
		fmt.Printf("removing %s: %v\n", ingressCgroupLinkPath, err)
	}
	if err := os.Remove(blockedMapPath); err != nil {
		fmt.Printf("removing %s: %v\n", blockedMapPath, err)
	}
}

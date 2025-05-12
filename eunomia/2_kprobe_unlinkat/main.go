package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 bpf kprobe.bpf.c -- -I../../cilium/headers
func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v\n", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("do_unlinkat", objs.DoUnlinkat, nil)
	if err != nil {
		log.Fatalf("Attaching object %s", err)
	}

	defer kp.Close()

	ticker := time.NewTicker(1*time.Second)
	log.Println("Waiting for events...")
	for range ticker.C {
		
	}
}

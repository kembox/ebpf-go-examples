package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf kprobe_percpu.c -- -I ../headers

const mapKey uint32 = 0

func main() {
	fn := "sys_execve"

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	defer objs.Close()

	kp, err := link.Kprobe(fn, objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("Opening kprobe: %s", err)
	}

	kp.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for event...")
	for range ticker.C {
		var all_cpu_value []uint64
		if err := objs.KprobeMap.Lookup(mapKey, &all_cpu_value); err != nil {
			log.Fatalf("reading map: %v", err)
		}

		for cpuid, cpuvalue := range all_cpu_value {
			log.Printf("%s called %d times on cpu %v\n", fn, cpuvalue, cpuid)
		}
		log.Println()
	}
}

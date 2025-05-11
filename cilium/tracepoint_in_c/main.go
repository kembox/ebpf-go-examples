//go: build linux

package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf tracepoint.c -- -I../headers

const mapKey uint32 = 0

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	defer objs.Close()

	kp, err := link.Tracepoint("kmem", "mm_page_alloc", objs.MmPageAlloc, nil)
	if err != nil {
		log.Fatalf("Attaching tracepoint: %s", err)
	}
	defer kp.Close()

	ticker := time.NewTicker(1 * time.Second)

	defer ticker.Stop()

	log.Println("waiting for events..")
	for range ticker.C {
		var value int64
		if err := objs.CountingMap.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}

		log.Printf("%v times", value)
	}
}

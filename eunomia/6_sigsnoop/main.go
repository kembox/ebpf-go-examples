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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 bpf sigsnoop.bpf.c -- -I../../cilium/headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove mem lock %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading bpf object %v", err)
	}
	defer objs.Close()

	kill_enter_link, err := link.Tracepoint("syscalls", "sys_enter_kill", objs.KillEntry, nil)
	if err != nil {
		log.Fatalf("link tracing kill enter %v", err)
	}
	defer kill_enter_link.Close()

	kill_exit_link, err := link.Tracepoint("syscalls", "sys_exit_kill", objs.KillExit, nil)
	if err != nil {
		log.Fatalf("link tracing kill exit %v", err)
	}
	defer kill_exit_link.Close()

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")
		os.Exit(0)
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		var (
			key   string
			value uint32
		)
		values := make(map[string]uint32)
		entries := objs.Values.Iterate()
		if entries == nil {
			log.Fatalf("nil map")
		} else {
			log.Print(entries)
		}
		log.Print("Start traversing hash map")
		for entries.Next(&key, &value) {
			log.Print("Inside iteration")
			values[key] = value
		}
		log.Print("Done iteration")
		if err := entries.Err(); err != nil {
			log.Fatalf("Iterator encountered an error: %v", err)
		}
		for k, v := range values {
			log.Printf("key: %s, value: %d\n", k, v)
		}
	}
}

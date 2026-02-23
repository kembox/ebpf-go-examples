//go:build linux

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 bpf runqlat.bpf.c -- -I../../cilium/headers

func main() {
	stopper := make(chan os.Signal,1)
	signal.Notify(stopper,os.Interrupt,syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove mem lock %v",err)
	}

}
//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 bpf runqlat.bpf.c -- -I../../cilium/headers

func main() {
	stopper := make(chan os.Signal,1)
	signal.Notify(stopper,os.Interrupt,syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove mem lock %v",err)
	}

	objs := bpfObjects{}

	if err := loadBpfObjects(&objs,nil); err != nil {
		log.Fatalf("loading bpf objects %v",err)
	}

	defer objs.Close()

	sched_wake_up_link, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "sched_wakeup",
		Program: objs.HandleSchedWakeup,
	})

	if err != nil {
		log.Fatalf("Attach raw tracepoint sched_wakeup %v",err)
	}

	defer sched_wake_up_link.Close()

	sched_wake_up_new_link, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "sched_wakeup_new",
		Program: objs.HandleSchedWakeupNew,
	})

	if err != nil {
		log.Fatalf("Attach raw tracepoint sched_wakeup_new %v",err)
	}

	defer sched_wake_up_new_link.Close()

	sched_switch_link, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "sched_switch",
		Program: objs.HandleSchedSwitch,
	})

	if err != nil {
		log.Fatalf("Attach raw tracepoint sched_switch %v",err)
	}

	defer sched_switch_link.Close()

	go func() {
		sig := <-stopper
		fmt.Printf("\nReceived signal: %v\n", sig )
		os.Exit(0)
	}()

	ticker := time.NewTicker(1 * time.Second)

	for range ticker.C {
		fmt.Println("Run queue latency historgram:")
		var key uint32
		var value bpfHist
		entries := objs.Hists.Iterate()

		for entries.Next(&key,&value) {
			fmt.Printf("comm %s latency %d\n",string(value.Comm[:]),value.Slots)
		}
	}

}
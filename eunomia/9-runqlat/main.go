//go:build linux

package main

import (
	"fmt"
	"flag"
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

	// filter_cg_ptr := flag.Bool("filter_cg",false,"filter the by cgroup")
	targ_per_process_ptr := flag.Bool("targ_per_process",false,"group runqueue latency by process")
	targ_per_thread_ptr := flag.Bool("targ_per_thread",false,"group runqueue latency by thread")
	// targ_per_pidns_ptr := flag.Bool("targ_per_pidns",false,"group runqueue latency by pid namespace")
	// targ_ms_ptr := flag.Bool("targ_ms",false,"set latency unit to miliseconds. Default to microseconds")

	flag.Parse()

	stopper := make(chan os.Signal,1)
	signal.Notify(stopper,os.Interrupt,syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove mem lock %v",err)
	}

	objs := bpfObjects{}

	// Load spec manually to edit global constant before LoadAndAssign
	// If not need to change global constant, just use `loadBpfObjects`
	// See https://ebpf-go.dev/concepts/global-variables/#static-global-variables
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading spec from binary %v",err)
	}

	/*
	for k := range(spec.Variables) {
		fmt.Printf("spec variable key: %s\n",k)
	}
	*/
	if err := spec.Variables["targ_per_process"].Set(*targ_per_process_ptr); err != nil {
		log.Fatalf("setting targ_per_process arg :%v",err)
	}

	if err := spec.Variables["targ_per_thread"].Set(*targ_per_thread_ptr); err != nil {
		log.Fatalf("setting targ_per_thread arg :%v",err)
	}


	// Load and assign spec to object 
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Load and Assign object %v",err)
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
//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 bpf exitsnoop.bpf.c -- -I../../cilium/headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove mem lock %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading bpf objects %v", err)
	}
	defer objs.Close()

	sched_process_exit_link, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		log.Fatalf("linking bpf program %v", err)
	}
	defer sched_process_exit_link.Close()

	rd, err := ringbuf.NewReader(objs.bpfMaps.Rb)
	if err != nil {
		log.Fatalf("opening ringbuf reader %v", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatalf("closing buffer: %v", err)
		}
	}()

	var event bpfEvent

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("receive signal, exiting")
				return
			}
			log.Printf("reading from buffer %v", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event %s", err)
		}
		log.Printf("Comm %s Pid %d PPid %d Exit_code %d Duration_ns %d", unix.ByteSliceToString(event.Comm[:]), event.Pid, event.Ppid, event.ExitCode, event.DurationNs)
	}
}

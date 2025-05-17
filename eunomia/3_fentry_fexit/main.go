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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf fentry.bpf.c -- -I../../cilium/headers

func main() {
	// Subscribe to signals to terminating the program
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	// &objs - pointer because we're populating its fields on the fly
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	link_entry, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.DoUnlinkat,
	})
	if err != nil {
		log.Fatal(err)
	}

	defer link_entry.Close()

	link_exit, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.DoUnlinkatExit,
	})

	if err != nil {
		log.Fatal(err)
	}

	defer link_exit.Close()

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatalf("opening ringubf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("receive signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf events: %s", err)
			continue
		}
		if event.Entry {
			log.Printf("Fentry event: pid: %d\tfilename: %s\n", event.Pid, unix.ByteSliceToString(event.Filename[:]))
		}
		log.Printf("Fexit event: pid: %d\tfilename: %s, return code: %d\n", event.Pid, unix.ByteSliceToString(event.Filename[:]), event.Ret)
	}
}

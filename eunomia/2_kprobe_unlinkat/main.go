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

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ring buf reader: %s", err)
	}

	defer rd.Close()

	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatalf("Closing ringbuf reader: %s", err)
		}
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Receive signal, exiting...")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ring buffer: %s", err)
			continue
		}

		log.Printf("pid: %d\tfilename: %s\n", event.Pid, unix.ByteSliceToString(event.Filename[:]))
	}
}

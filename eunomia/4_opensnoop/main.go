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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf opensnoop.bpf.c -- -I../../cilium/headers
func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove mem lock limit: %s", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading object %s", err)
	}
	defer objs.Close()

	tplink, err := link.Tracepoint("syscalls", "sys_enter_at", objs.TraceSyscallsSysEnterAt, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %s", err)
	}
	defer tplink.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ring buffer reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuffer reader: %s", err)
		}
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()

		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal. exiting")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
		}
		log.Printf("Command %s pid %d open file %s\n", unix.ByteSliceToString(event.Comm[:]), event.Pid, unix.ByteSliceToString(event.Filename[:]))
	}

}

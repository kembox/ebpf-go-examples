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

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader %s", err)
	}

	defer rd.Close()

	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatalf("closing buffer: %s", err)
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
			log.Printf("reading from buffer: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ring buffer event %s", err)
			continue
		}
		log.Printf("PID %d (%s) sent signal %d to PID %d, ret = %d", event.Pid, unix.ByteSliceToString(event.Comm[:]), event.Sig, event.Tpid, event.Ret)
	}
}

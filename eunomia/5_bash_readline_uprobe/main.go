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

const (
	binPath = "/bin/bash"
	symbol  = "readline"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 bpf bash_readline_uprobe.bpf.c -- -I../cilium/headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading object %v", err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	uretp, err := ex.Uretprobe(symbol, objs.bpfPrograms.Printret, nil)
	if err != nil {
		log.Fatalf("linking object: %v", err)
	}
	defer uretp.Close()

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
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

		log.Printf("clgt")
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("receive signal, exiting")
				return
			}
			log.Printf("reading from buffer: %s", err)
			continue
		}
		log.Printf("vltn")

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ring buff event %s", err)
			continue
		}
		log.Printf("kretprobe event: PID %d comm %s ret %s", event.Pid, unix.ByteSliceToString(event.Comm[:]), unix.ByteSliceToString(event.Ret[:]))

	}
}

//go:build linux

package main

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

var progSpec = &ebpf.ProgramSpec{
	Name:    "my_trace_prog",
	Type:    ebpf.TracePoint,
	License: "GPL",
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
		Name: "my_perf_array",
	})

	if err != nil {
		log.Fatalf("creating perf event array: %s", err)
	}
	defer events.Close()

	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}

	defer rd.Close()
	go func() {
		<-stopper
		rd.Close()
	}()

	progSpec.Instructions = asm.Instructions{
		// store the integer 123 at FP[-8]
		asm.Mov.Imm(asm.R2, 127),
		// store value in R2 as 32 bit value at offset -8 from FP
		// why 8 bytes offset for 32 bit value ?
		// Doesn't matter much. We can put it at any offset
		// Store to RFP - 8 offset, not RFP itself. RFP = R10 is a read-only frame pointer
		// asm.StoreMem(asm.RFP, -8, asm.R2, asm.Word),
		asm.StoreMem(asm.RFP, -128, asm.R2, asm.Word),

		// store pointer of bpf map `events` to R2 register
		asm.LoadMapPtr(asm.R2, events.FD()),

		// Load value 0xffffffff of Dword 64 bit size to R3 register
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),

		// Move value of FP to R4
		asm.Mov.Reg(asm.R4, asm.RFP),

		// Add -8 to R4
		// asm.Add.Imm(asm.R4, -8),
		asm.Add.Imm(asm.R4, -128),
		// Add 4 to R5
		asm.Mov.Imm(asm.R5, 4),

		// See https://docs.ebpf.io/linux/helper-function/bpf_perf_event_output/
		// Argument list so far:
		// R1 not set - *ctx
		// R2: pointer to `events` map  -  map
		// R3: 0xffffffff - flags
		// R4: FP - 8 ( 123 ? ) - data
		// R5: 4 - size
		asm.FnPerfEventOutput.Call(),

		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		log.Fatalf("creating ebpf program: %s", err)
	}

	defer prog.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}

	defer tp.Close()

	log.Println("Waiting for events..")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting...")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		// log.Printf("Type of record: %T", record)
		log.Println("Record: ", record.RawSample[0])
	}

}

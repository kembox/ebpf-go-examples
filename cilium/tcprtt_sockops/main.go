//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type rtt_event bpf tcprtt_sockops.c -- -I ../headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	cgroupPath, err := findCgroupPath()
	if err != nil {
		log.Fatalf("Finding cgroup path %s", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading object: %v", err)
	}
	defer objs.Close()

	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.bpfPrograms.BpfSockopsCb,
		Attach:  ebpf.AttachCGroupSockOps,
	})

	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()
	log.Printf("eBPF program loaded and attached on cgroup %s\n", cgroupPath)

	rd, err := ringbuf.NewReader(objs.bpfMaps.RttEvents)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}

	defer rd.Close()
	log.Printf("%-15s %-6s -> %-15s %-6s %-6s",
		"src_addr",
		"port",
		"dest_addr",
		"port",
		"rtt (ms)",
	)
	go readLoop(rd)

	<-stopper

}

func findCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"
	var st syscall.Statfs_t
	err := syscall.Statfs(cgroupPath, &st)
	if err != nil {
		return "", err
	}

	isCgroupV2Enabled := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgroupV2Enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}
	return cgroupPath, nil
}

func readLoop(rd *ringbuf.Reader) {
	var event bpfRttEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("Reading from reader: %s", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		log.Printf("%-15s %-6d -> %-15s %-6d %-6d",
			intToIp(event.Saddr),
			event.Sport,
			intToIp(event.Daddr),
			event.Dport,
			event.Srtt,
		)
	}
}

func intToIp(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

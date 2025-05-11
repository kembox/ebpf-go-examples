//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf xdp.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatal("please specify network interface")
	}

	// Look up the interface by name
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("detecting network interface %q: %s", iface.Name, err)
	}

	// Load pre-compile program into kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading bpf object: %s", err)
	}

	defer objs.Close()

	// Attach the program
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	defer l.Close()

	log.Printf("Attach XDP program to interface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s, err := formatMapContents(objs.XdpStatsMap)
		if err != nil {
			log.Printf("error loading map: %s", err)
			continue
		}
		log.Printf("Map content: \n%s", s)
	}
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key netip.Addr
		val uint32
	)

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := key
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%s=> %d\n", sourceIP, packetCount))
	}
	return sb.String(), iter.Err()
}

//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf tcx.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("you must specific a network interface")
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network interface %q: %s", ifaceName, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading bpf objects: %s", err)
	}
	defer objs.Close()

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IngressProgFunc,
		Attach:    ebpf.AttachTCXIngress,
	})

	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}

	defer l.Close()

	log.Printf("attach tcx program to interface %q ( index %d)", iface.Name, iface.Index)

	l2, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.EgressProgFunc,
		Attach:    ebpf.AttachTCXEgress,
	})

	if err != nil {
		log.Fatalf("attaching bpfprogram to egress interface %s", err)
	}

	defer l2.Close()

	log.Printf("Attached TCx program to EGRESS iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatCounter(objs.IngressPktCount, objs.ExgressPktCount)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}

		log.Printf("Packet count: %s\n", s)
	}
}

func formatCounter(ingressVar, egressVar *ebpf.Variable) (string, error) {
	var (
		ingressPacketCount uint64
		egressPacketCount  uint64
	)

	// retrieve value from the ingress map
	if err := ingressVar.Get(&ingressPacketCount); err != nil {
		return "", err
	}

	// retrieve value from the egress map
	if err := egressVar.Get(&egressPacketCount); err != nil {
		return "", err
	}

	return fmt.Sprintf("%10v Ingress, %10v Egress", ingressPacketCount, egressPacketCount), nil
}

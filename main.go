package main

import (
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func loadHanaToInterface(ifname string, objs hanaObjects) link.Link {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Hana,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	return link
}

func insert_target_node(targetNodes *ebpf.Map, counterMap *ebpf.Map) {
	log.Printf("Inserting target node to map")
	n := &Node{"84:2f:57:4e:34:d7", "192.168.1.100", 8000}
	node, err := TargetNodeFromNode(n)
	if err != nil {
		panic(err)
	}
	var node_counter_index uint32 = 0
	var first_node_position_index uint32 = 0
	var val uint32 = 1
	log.Printf("Updating counter map node_count value to 1")
	counterMap.Update(node_counter_index, &val, ebpf.UpdateAny)
	log.Printf("Inserting targetNode")
	log.Printf("Ip: %d, mac: %d, port: %d", node.Ip_addr, node.Mac_addr, node.Port)
	err = targetNodes.Update(first_node_position_index, node, ebpf.UpdateAny)
	if err != nil {
		panic(err)
	}
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs hanaObjects
	if err := loadHanaObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := "enx00e04cbbca1d"
	link := loadHanaToInterface(ifname, objs)
	defer link.Close()
	insert_target_node(objs.TargetNodes, objs.CounterMap)

	log.Printf("Counting incoming packets on %s..", ifname)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}

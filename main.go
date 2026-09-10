package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	model "hana-ebpf/model"
	"log"
	"net"
	"os"
	"os/signal"
)

func attachXDPToNetworkInterface(ifname string, objs hanaObjects) link.Link {
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

func insert_target_node(nodeList []model.NodeList, targetNodes *ebpf.Map, counterMap *ebpf.Map) {
	log.Printf("Inserting nodes to targetNodesMap")
	nodeCount := uint32(len(nodeList))
	for i := uint32(0); i < nodeCount; i++ {
		target_node, err := model.TargetNodeFromNode(&nodeList[i].Nodes)
		if err != nil {
			panic(err)
		}
		err = targetNodes.Update(i, target_node, ebpf.UpdateAny)
		if err != nil {
			panic(err)
		}
	}
	counterMap.Update(uint32(0), &nodeCount, ebpf.UpdateAny)
	log.Printf("Inserted %d nodes into map", nodeCount)
}

func main() {
	if len(os.Args) != 2 {
		panic("Expected path to properties file argv[1]")
	}
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
	var properties model.Properties
	properties.ReadPropertiesFile(os.Args[1])
	log.Println(properties)

	ifname := properties.NetworkInterface

	insert_target_node(properties.Nodes, objs.TargetNodes, objs.CounterMap)
	link := attachXDPToNetworkInterface(ifname, objs)
	defer link.Close()

	log.Printf("Load balancer attached on %s", ifname)

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	_ = <-stop
}

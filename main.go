package main

import (
	model "hana-ebpf/model"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
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

func whiteListTargetNodes(targetNodes [] model.NodeList, whiteListIps *ebpf.Map){
		tmp := make([] uint32, 0, len(targetNodes))
		nodeIps := make([] uint32, 0, len(targetNodes))
		for i := 0; i < len(targetNodes); i++ {
			targetNode, err := model.TargetNodeFromNode(&targetNodes[i].Node)
			if err != nil {
				panic(err);
			}
			nodeIps = append(nodeIps, targetNode.Ip_addr)
			tmp = append(tmp, 1)
		}
		updateCount, err := whiteListIps.BatchUpdate(nodeIps, tmp, nil)
		if err != nil {
			panic(err)
		}
		log.Printf("Whitelisted %d ips", updateCount)
}

func updateNodeMap(healthyNodesChannel chan [] model.Node, targetNodes *ebpf.Map, counterMap *ebpf.Map) {
	for ;; {
		log.Printf("Waiting for healthy nodes")
		healthyNodes := <- healthyNodesChannel
		if len(healthyNodes) == 0 {
			log.Printf("No nodes are healthy")
			continue;
		}
		log.Printf("Inserting nodes to targetNodesMap")
		nodeCount := uint32(len(healthyNodes))
		indexes := make([] uint32, 0, nodeCount)
		nodesMapped := make([] model.TargetNode,0, nodeCount)
		for i := uint32(0); i < nodeCount; i++ {
			targetNode, err := model.TargetNodeFromNode(&healthyNodes[i])
			if err != nil {
				panic(err)
			}
			indexes = append(indexes, i)
			nodesMapped = append(nodesMapped, *targetNode)
		}
		updatedCount, err := targetNodes.BatchUpdate(indexes, nodesMapped, &ebpf.BatchOptions{ElemFlags: 0, Flags: uint64(ebpf.UpdateAny)});
		if err != nil {
			panic(err)
		}
		counterMap.Update(uint32(0), &nodeCount, ebpf.UpdateAny)
		log.Printf("Inserted %d nodes into map %s", updatedCount, healthyNodes)
	}
}

func startHealthcheck(nodeList [] model.NodeList, healthCheck* model.Healthcheck, healthyNodesChannel chan [] model.Node){
	log.Println("Checking health of nodes")
	healthChan := make(chan HealthcheckEnvelope, len(nodeList))
	for ;;{
		healthyNodesId := make([]model.Node, 0, len(nodeList))
		for i := 0; i < len(nodeList); i++ {
			go CheckHealth(nodeList[i].Node, healthCheck, healthChan, uint32(i));
		}
		for i := 0; i < len(nodeList); i++ {
			healthCheckResult := <- healthChan
			log.Println("Result of healthcheck: ", healthCheckResult.Alive, " for node : ", healthCheckResult.NodeId)
			if healthCheckResult.Alive {
				healthyNodesId = append(healthyNodesId, nodeList[healthCheckResult.NodeId].Node)
			}
		}
		healthyNodesChannel <- healthyNodesId
		time.Sleep(30 * time.Second)
	}
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

	healthyNodesChannel := make(chan [] model.Node)
	ifname := properties.NetworkInterface
	whiteListTargetNodes(properties.Nodes, objs.WhitelistIps)
	go startHealthcheck(properties.Nodes, &properties.Healthcheck, healthyNodesChannel)
	go updateNodeMap(healthyNodesChannel, objs.TargetNodes, objs.CounterMap)
	link := attachXDPToNetworkInterface(ifname, objs)
	defer link.Close()

	log.Printf("Load balancer attached on %s", ifname)

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	_ = <-stop
}

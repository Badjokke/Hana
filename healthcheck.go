package main

import (
	model "hana-ebpf/model"
	"net"
	"log"
	"time"
	"bytes"
	)
const HEALTHCHECK_TIMEOUT_SECONDS = 20

type HealthcheckEnvelope struct  {
	NodeId uint32
	Alive bool
};

func CheckHealth(node model.Node, healthcheck *model.Healthcheck, statusChannel chan HealthcheckEnvelope, id uint32){
	buf := make([]byte, len(healthcheck.Response))
	addr := net.UDPAddr{IP: net.ParseIP(node.Ip_addr), Port: int(healthcheck.Port)}
	socket, err := net.DialUDP("udp", nil, &addr)
	socket.SetReadDeadline(time.Now().Add(HEALTHCHECK_TIMEOUT_SECONDS * time.Second));
	if err != nil {
		log.Println(err)
		statusChannel <- failed(id);
		return;
	}
	msgBytes := []byte(healthcheck.Message)
	socket.Write(msgBytes)
	bytesRead, err := socket.Read(buf)
	log.Println("Recieved ", bytesRead, " bytes from ", addr)
	if err != nil {
		log.Println("Healthcheck failed for node: ", node, " TIME OUT")
		statusChannel <- failed(id);
		return;
	}
	if !bytes.Equal([]byte(healthcheck.Response), buf){
		log.Println("Healthcheck failed for node: ", string(buf), ":", string(healthcheck.Response), " RESPONSE MISSMATCH")
		statusChannel <- failed(id);
		return;
	}
	statusChannel <- alive(id);
}


func failed(nodeId uint32) HealthcheckEnvelope{
	return HealthcheckEnvelope{NodeId: nodeId, Alive: false}
}

func alive(nodeId uint32) HealthcheckEnvelope{
	return HealthcheckEnvelope{NodeId: nodeId, Alive: true}
}

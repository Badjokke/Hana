package model

import (
	"errors"
	"log"
	"strconv"
	"strings"
)

const ETH_ALEN = 6
const IP_LEN = 4
const IP_DELIMITER = "."
const MAC_ADDR_DELIMITER = ":"

type Node struct {
	Mac_addr string `yaml:"mac_addr"`
	Ip_addr  string `yaml:"ip_addr"`
	Port     uint16 `yaml:"port"`
}

type TargetNode struct {
	Mac_addr [ETH_ALEN]byte
	Pad0     [2]byte
	Ip_addr  uint32
	Port     uint16
	Pad1     [2]byte
}

func TargetNodeFromNode(node *Node) (*TargetNode, error) {
	ip_addr_be32, err := node.Ip_addr_to_be32()
	if err != nil {
		return nil, err
	}
	mac_addr_bytes, err := node.Mac_addr_to_bytes()
	if err != nil {
		return nil, err
	}
	return &TargetNode{Ip_addr: ip_addr_be32, Mac_addr: [ETH_ALEN]byte(mac_addr_bytes), Port: node.Port_to_be()}, nil
}

func (node *Node) Ip_addr_to_be32() (uint32, error) {
	parts := strings.Split(node.Ip_addr, IP_DELIMITER)
	if len(parts) != IP_LEN {
		log.Printf("ip addr: %s is not valid", node.Ip_addr)
		return 0, errors.New("Ip address must have 4 bytes separated by '.'")
	}
	var ip int = 0
	for i := 0; i < IP_LEN; i += 1 {
		tmp, err := strconv.Atoi(parts[i])
		if err != nil {
			return 0, err
		}
		ip |= tmp << (8 * i)
	}
	return uint32(ip), nil
}

func (node *Node) Mac_addr_to_bytes() ([]byte, error) {
	parts := strings.Split(node.Mac_addr, MAC_ADDR_DELIMITER)
	if len(parts) != ETH_ALEN {
		return nil, errors.New("Mac address must have 6 bytes separated by ':'")
	}
	result := make([]byte, ETH_ALEN)
	for i := 0; i < ETH_ALEN; i++ {
		tmp, err := strconv.ParseInt(parts[i], 16, 16)
		if err != nil {
			return nil, err
		}
		result[i] = byte(tmp)
	}
	return result, nil
}

func (node *Node) Port_to_be() uint16 {
	var be_port uint16 = 0
	be_port |= (node.Port & 0xFF) << 8
	be_port |= (node.Port >> 8) & 0xFF
	return be_port
}

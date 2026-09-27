#pragma once
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#define TARGET_NODE_SIZE 3
/* XDP load balancer for ip protocol family. Current support for UDP.*/
// 1500 mtu ethernet frame for standard NIC without IP header size
#define IP4_PROT_ETH_TYPE 0x0008
#define ETH_HDR_SIZE 14
#define IP_HDR_SIZE 20
#define UDP_PROT 0x11
#ifndef mem
        #define memcpy(dest, src, n) __builtin_memcpy((dest), (src), n)
#endif

// node to which the network packet will be redirected to
struct node {
  unsigned char mac_addr[ETH_ALEN];
  __be32 ip_addr;
};

// stores the number of inserted target nodes at index 0
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 1);
} counter_map SEC(".maps");

// populated by userspace application
// stores the actual nodes we forward udp traffic to
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct node);
  __uint(max_entries, TARGET_NODE_SIZE);
} target_nodes SEC(".maps");

// populated by userspace application
// network order ipv4 addr that is passed
// up the kernel stack. Used to make healthcheck work
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __be32);
  __uint(max_entries, TARGET_NODE_SIZE);
} whitelist_ips SEC(".maps");


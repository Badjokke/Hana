#pragma once
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#define TARGET_NODE_SIZE 10
#define CONN_TRACK_SIZE 200
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
  __be16 port;
};

// stores the number of inserted target nodes at index 0
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 1);
} counter_map SEC(".maps");

// populated by userspace application
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct node);
  __uint(max_entries, TARGET_NODE_SIZE);
} target_nodes SEC(".maps");

// used to retrieve the next value for ephemeral port
// necessary for conn-tracking heurestic
// __u32 used as a value for atomic operation support
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 1);
} port_counter SEC(".maps");

// used to send responses
// map is periodically cleaned from userspace
// key = node->ip_addr xor node->port
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32);
  __type(value, struct node);
  __uint(max_entries, CONN_TRACK_SIZE);
} conn_track SEC(".maps");

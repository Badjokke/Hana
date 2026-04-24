#pragma once
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#define TARGET_NODE_SIZE 2 << 10
#define CONN_TRACK_SIZE 2 << 14
/* XDP load balancer for ip protocol family. Current support for UDP.*/
// 1500 mtu ethernet frame for standard NIC without IP header size
#define IP4_PROT_ETH_TYPE 0x0008
#define ETH_HDR_SIZE 14
#define IP_HDR_SIZE 20
#define UDP_PROT 0x11
#ifndef mem
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), n)
#endif

// todo how to clean up maps
struct node {
  char mac_addr[ETH_ALEN];
  __be32 ip_addr;
  __be16 port;
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 1);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} counter_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct node);
  __uint(max_entries, TARGET_NODE_SIZE);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} target_nodes SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, struct node);
  __uint(max_entries, CONN_TRACK_SIZE);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} conn_track SEC(".maps");

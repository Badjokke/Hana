//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include "hana_kern.h"
#include "checksum.h"

static void* data_pointer_at(void* data, void* data_end, __u64 offset, __u64 size){
	if (data + offset + size > data_end){
		return NULL;
	}
	return (void*) (data + offset);
}


static struct node* retrieve_node_from_target_nodes() {
	__u32 node_count_index = 0;
	__u32* node_count = bpf_map_lookup_elem(&counter_map, &node_count_index);
	if (node_count == NULL || (*node_count) == 0) {
		return NULL;
	}
	__u32 node_pointer = bpf_get_prandom_u32() % (*node_count);
	struct node* node = bpf_map_lookup_elem(&target_nodes, &node_pointer);
	return node;
}


// applies node to ip and ether header
static void apply_node_to_ip_ether_headers(struct node* node, struct ethhdr* ether_header, struct iphdr* iphdr){
	memcpy(ether_header->h_source, ether_header->h_dest, ETH_ALEN);
	memcpy(ether_header->h_dest, node->mac_addr, ETH_ALEN);
	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = node->ip_addr;
}


static int forward_udp_traffic_to_node(struct ethhdr* ether_header, struct iphdr* iphdr, struct udphdr* udp_header, void* data_end){
	struct node* target_node = retrieve_node_from_target_nodes();
	if (target_node == NULL){
		return XDP_DROP;
	}
	apply_node_to_ip_ether_headers(target_node, ether_header, iphdr);
	iphdr->check = ip_checksum(iphdr, IP_HDR_SIZE);
	udp_header->check = udp_checksum(udp_header, iphdr, data_end);
	return XDP_TX;
}


static int forward_traffic(void* data, void* data_end, struct ethhdr* ether_header){
	struct iphdr* iphdr = (struct iphdr*) data_pointer_at(data, data_end, ETH_HDR_SIZE, IP_HDR_SIZE);
	if (iphdr == NULL) {
		return XDP_DROP;
	}
	if (iphdr->protocol != UDP_PROT ){
		return XDP_PASS;
	}

	struct udphdr* udp_header = (struct udphdr*) data_pointer_at(data, data_end, ETH_HDR_SIZE + IP_HDR_SIZE, sizeof(struct udphdr));
	if ( udp_header == NULL ) {
		return XDP_DROP;
	}
	return forward_udp_traffic_to_node(ether_header, iphdr, udp_header, data_end);
}

SEC("xdp")
int hana(struct xdp_md* ctx){
	void* data = (void*) (long) ctx->data;
	void* data_end = (void*) (long) ctx->data_end;
	struct ethhdr* ether_header = (struct ethhdr*) data_pointer_at(data, data_end, 0, ETH_HDR_SIZE);
	if (ether_header == NULL || ether_header->h_proto != IP4_PROT_ETH_TYPE){
		return XDP_PASS;
	}
	return forward_traffic(data, data_end, ether_header);
}

char _license[] SEC("license") = "Dual MIT/GPL";

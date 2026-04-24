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
	__u32 first_element_index = 0;
	__u32* current_walker_value = bpf_map_lookup_elem(&counter_map, &first_element_index);
	if (current_walker_value == NULL) {
		__u32 tmp = 0;
		current_walker_value = &tmp;
	}
	static const char fmt[] = "accessing node at index %d";
	bpf_trace_printk(fmt, sizeof(fmt), *current_walker_value);
	struct node* node = bpf_map_lookup_elem(&target_nodes, current_walker_value);
	if (node == NULL){
		static const char fmt[] = "no node found for at index: %d";
		bpf_trace_printk(fmt, sizeof(fmt), *current_walker_value);
	}
	__u32 updated_walker_value = (*current_walker_value + 1) % TARGET_NODE_SIZE;
	//__sync_fetch_and_add(current_walker_value, 1);
	bpf_map_update_elem(&counter_map, &first_element_index, &updated_walker_value, 0);
	return node;
}

static int forward_via_gateway(struct ethhdr* ether_header, struct iphdr* iphdr, struct udphdr* udp_header, void* data_end){
	struct node* target_node = retrieve_node_from_target_nodes();
	if (target_node == NULL){
		return XDP_DROP;
	}

	memcpy(ether_header->h_source, ether_header->h_dest, ETH_ALEN);
	memcpy(ether_header->h_dest, target_node->mac_addr, ETH_ALEN);

	iphdr->daddr = target_node->ip_addr;
	iphdr->check = 0;
	iphdr->check = ip_checksum((__u16*) iphdr, IP_HDR_SIZE);
	udp_header->dest = target_node->port;
	udp_header->check = 0;
	udp_header->check = udp_checksum(udp_header, iphdr, data_end);
	return XDP_TX;
}

static int forward_traffic(void* data, void* data_end, struct ethhdr* ether_header){
	struct iphdr* iphdr = (struct iphdr*) data_pointer_at(data, data_end, ETH_HDR_SIZE, IP_HDR_SIZE);
	if (iphdr == NULL) {
		return XDP_DROP;
	}
	if (iphdr->protocol != UDP_PROT) {
		static const char fmt[] = "Only UDP currently supported.";
		bpf_trace_printk(fmt, sizeof(fmt), iphdr->protocol, UDP_PROT);
		return XDP_PASS;
	}
	struct udphdr* udp_header = (struct udphdr*) data_pointer_at(data, data_end, ETH_HDR_SIZE + IP_HDR_SIZE, sizeof(struct udphdr));
	if ( udp_header == NULL ) {
		static const char fmt[] = "UDP hdr is null";
		bpf_trace_printk(fmt, sizeof(fmt), iphdr->protocol, UDP_PROT);
		return XDP_DROP;
	}
	return forward_via_gateway(ether_header, iphdr, udp_header, data_end);
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

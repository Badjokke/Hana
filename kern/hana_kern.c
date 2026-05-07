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
	if ((*node_count) == 0) {
		return NULL;
	}
	__u32 node_pointer = bpf_get_prandom_u32() % (*node_count);
	struct node* node = bpf_map_lookup_elem(&target_nodes, &node_pointer);
	return node;
}

static __u16 get_ephemeral_port_number(){
	__u32 port_number_index = 0;
	__u32* port_number = bpf_map_lookup_elem(&port_counter, &port_number_index);
	__sync_fetch_and_add(port_number, 1);
	__u16 ephemeral_port_number = *port_number % (2 << 16);
	return ephemeral_port_number;
}

static struct node* retrieve_node_from_conntrack(struct iphdr* iphdr, struct udphdr* udp_header){
	__u32 key = iphdr->saddr ^ udp_header->dest;
	return bpf_map_lookup_elem(&conn_track, &key);
}

static void create_conntrack_entry(struct node* target_node, struct iphdr* iphdr, struct udphdr* udp_header, struct ethhdr* ether_header, __be16 ephemeral_port){
	struct node node = {};
	memcpy(node.mac_addr, ether_header->h_source, ETH_ALEN);
	node.ip_addr = iphdr->saddr;
	node.port = udp_header->source;
	__u32 key = target_node->ip_addr ^ ephemeral_port;
	bpf_map_update_elem(&conn_track, &key, &node, BPF_ANY);
}

static void apply_node_to_packet(struct node* node, struct ethhdr* ether_header, struct iphdr* iphdr, struct udphdr* udp_header, __be16 ephemeral_port){
	memcpy(ether_header->h_source, ether_header->h_dest, ETH_ALEN);
	memcpy(ether_header->h_dest, node->mac_addr, ETH_ALEN);
	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = node->ip_addr;
	udp_header->dest = node->port;
	udp_header->source = ephemeral_port;
}

static int forward_traffic_to_node(struct ethhdr* ether_header, struct iphdr* iphdr, struct udphdr* udp_header, void* data_end){
	struct node* target_node = retrieve_node_from_conntrack(iphdr, udp_header);
	if (target_node == NULL) {
		target_node = retrieve_node_from_target_nodes();
	}
	
	if (target_node == NULL){
		static const char fmt[] = "No target nodes available. Dropping traffic. Saddr: %d source: %d";
		bpf_trace_printk(fmt, sizeof(fmt), iphdr->saddr, udp_header->source);
		return XDP_DROP;
	}
	__be16 ephemeral_port = bpf_htons(get_ephemeral_port_number());

        create_conntrack_entry(target_node, iphdr, udp_header, ether_header, ephemeral_port);
	apply_node_to_packet(target_node, ether_header, iphdr, udp_header, ephemeral_port);
	iphdr->check = ip_checksum(iphdr, IP_HDR_SIZE);
	udp_header->check = udp_checksum(udp_header, iphdr, data_end);
	return XDP_TX;
}

static int forward_traffic(void* data, void* data_end, struct ethhdr* ether_header){
	struct iphdr* iphdr = (struct iphdr*) data_pointer_at(data, data_end, ETH_HDR_SIZE, IP_HDR_SIZE);
	if (iphdr == NULL) {
		return XDP_DROP;
	}
	if (iphdr->protocol != UDP_PROT) {
		return XDP_PASS;
	}
	struct udphdr* udp_header = (struct udphdr*) data_pointer_at(data, data_end, ETH_HDR_SIZE + IP_HDR_SIZE, sizeof(struct udphdr));
	if ( udp_header == NULL ) {
		return XDP_DROP;
	}
	return forward_traffic_to_node(ether_header, iphdr, udp_header, data_end);
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

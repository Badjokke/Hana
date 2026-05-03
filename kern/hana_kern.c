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

static int __always_inline is_empty_node_struct(struct node* node){
	return node->port == 0 && node->ip_addr == 0 && node->mac_addr[0] == 0;
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

// if MASQ node is configured from userspace we will hide source node under shared mac/ip/port
static struct node* retrieve_MASQ(){
	__u32 key = 0;
	struct node* masq_node = bpf_map_lookup_elem(&masquerade, &key);
	if (is_empty_node_struct(masq_node)){
		return NULL;
	}
	return masq_node;
}

static struct conntrack_node* retrieve_node_from_conntrack(struct iphdr* iphdr, struct udphdr* udp_header){
	__u32 key = iphdr->saddr ^ udp_header->source;
	return bpf_map_lookup_elem(&conn_track, &key);
}

static void create_conntrack_entry(struct node* target_node, struct iphdr* iphdr, struct udphdr* udp_header, struct ethhdr* ether_header){
	struct node node = {};
	memcpy(node.mac_addr, ether_header->h_source, ETH_ALEN);
	node.ip_addr =  iphdr->saddr;
	node.port = udp_header->source;
	__u64 insertion_timestamp = bpf_ktime_get_ns();
	__u32 key = target_node->ip_addr ^ target_node->port;
	struct conntrack_node conntrack_node = {.node =  node, .timestamp =  insertion_timestamp};
	bpf_map_update_elem(&conn_track, &key, &conntrack_node, BPF_ANY);
}

static void apply_node_to_packet(struct node* node, struct ethhdr* ether_header, struct iphdr* iphdr, struct udphdr* udp_header, void* data_end){
	struct node* masq_node = retrieve_MASQ();
	if (masq_node != NULL){
		static const char fmt[] = "MASQ node found.";
		bpf_trace_printk(fmt, sizeof(fmt));
		memcpy(ether_header->h_source, masq_node->mac_addr, ETH_ALEN);
		udp_header->source = masq_node->port != 0 ? masq_node->port : node->port;
		iphdr->saddr = node->ip_addr;
	}
	memcpy(ether_header->h_dest, node->mac_addr, ETH_ALEN);
	iphdr->daddr = node->ip_addr;
	iphdr->check = ip_checksum(iphdr, IP_HDR_SIZE);
	udp_header->dest = node->port;
	udp_header->check = udp_checksum(udp_header, iphdr, data_end);
	static const char fmt[] = "%d %d";
	bpf_trace_printk(fmt, sizeof(fmt), iphdr->daddr, udp_header->dest);
}

static int conntrack_forward(struct conntrack_node* conntrack_node, struct ethhdr* ether_header, struct iphdr* iphdr, struct udphdr* udp_header, void* data_end){
	struct node node = conntrack_node->node;
	apply_node_to_packet(&conntrack_node->node, ether_header, iphdr, udp_header, data_end);
	__u64 updated_timpestamp = bpf_ktime_get_ns();
	conntrack_node->timestamp = updated_timpestamp;
	__u32 key = node.ip_addr ^ node.port;
	bpf_map_update_elem(&conn_track, &key, conntrack_node, BPF_EXIST);
	return XDP_TX;
}

static int forward_traffic_to_node(struct ethhdr* ether_header, struct iphdr* iphdr, struct udphdr* udp_header, void* data_end){
	/*struct conntrack_node* conntrack_node = retrieve_node_from_conntrack(iphdr, udp_header);
	if (conntrack_node != NULL) {
		static const char fmt[] = "Conntrack node found";
		bpf_trace_printk(fmt, sizeof(fmt));
		return conntrack_forward(conntrack_node, ether_header, iphdr, udp_header, data_end);
	}*/
	struct node* target_node = retrieve_node_from_target_nodes();
	if (target_node == NULL){
		static const char fmt[] = "No target nodes available. Dropping traffic.";
		bpf_trace_printk(fmt, sizeof(fmt));
		return XDP_DROP;
	}
	apply_node_to_packet(target_node, ether_header, iphdr, udp_header, data_end);
        create_conntrack_entry(target_node, iphdr, udp_header, ether_header);
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

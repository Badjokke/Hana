#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
/* XDP load balancer for ip protocol family. Current support for UDP.*/
// 1500 mtu ethernet frame for standard NIC without IP header size
#define MAX_PAYLOAD_SIZE 1480
#define IP4_PROT_ETH_TYPE 0x0008
#define ETH_HDR_SIZE 14
#define IP_HDR_SIZE 20

static __always_inline void* data_pointer_at(void* data, void* data_end, __u64 offset, __u64 size){
	if (data + offset + size > data_end){
		return NULL;
	}
	return (void*) (data + offset);
}

__u16 ip_checksum(__u16* bfr, int count) {
	unsigned long sum = 0;
	while (count > 1) {
		sum += *bfr;
		bfr++;
		count-= 2;
	}
	if (count > 1) {
		sum += * (unsigned char*) bfr;
	}
	while( sum >> 16 > 0) {
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
	return ~sum;
}

int forward_ip_traffic(void* data, void* data_end, struct ethhdr* ether_header){
	struct iphdr* iphdr = (struct iphdr*) data_pointer_at(data, data_end, ETH_HDR_SIZE, IP_HDR_SIZE);
	if (iphdr == NULL) {
		return XDP_DROP;
	}
	__u16 check = iphdr->check;
	iphdr->check = 0;
	__u16 _check = ip_checksum((__u16*) iphdr, IP_HDR_SIZE);
	static const char fmt[] = "%d %d";
	bpf_trace_printk(fmt, sizeof(fmt), check, _check);
	return XDP_PASS;
}

SEC("xdp")
int balancer(struct xdp_md* ctx){
	void* data = (void*) (long) ctx->data;
	void* data_end = (void*) (long) ctx->data_end;
	struct ethhdr* ether_header = (struct ethhdr*) data_pointer_at(data, data_end, 0, ETH_HDR_SIZE);
	if (ether_header == NULL || ether_header->h_proto != IP4_PROT_ETH_TYPE){
		return XDP_DROP;
	}

	return forward_ip_traffic(data, data_end, ether_header);
}

char _license[] SEC("license") = "GPL";

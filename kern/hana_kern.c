#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/ip.h>
/* XDP load balancer for ip protocol family. Current support for UDP.*/
// 1500 mtu ethernet frame for standard NIC without IP header size
#define MAX_PAYLOAD_SIZE 1480
#define IP4_PROT_ETH_TYPE 0x0008
#define ETH_HDR_SIZE 14
#define IP_HDR_SIZE 20
#define UDP_PROT 0x11

static  __always_inline void* data_pointer_at(void* data, void* data_end, __u64 offset, __u64 size){
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
		sum += * (__u8*) bfr;
	}
	while( sum >> 16 > 0) {
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
	return ~sum;
}

__u32 pseudoheader_checksum(struct iphdr* iphdr) {
	__u32 sum = 0;
	sum += (__u16)iphdr->saddr;
	sum += (__u16)(iphdr->saddr >> 16);
	sum += (__u16)iphdr->daddr;
	sum += (__u16)(iphdr->daddr >> 16);
	sum += (__u16)iphdr->protocol << 8;
	return sum;
}

__u16 udp_checksum(struct udphdr* udphdr, struct iphdr* iphdr, void* data_end){
	__u32 sum = pseudoheader_checksum(iphdr);
	__u16* bfr = (__u16*) udphdr;
	__u16 count = MAX_PAYLOAD_SIZE;
	sum += udphdr->len;
	while(count > 1){
		if( (void*)(bfr + 1) > data_end) {
			break;
		}
		sum += *bfr;
		bfr++;
		count -= 2;
	}
	//payload is not 2 bytes aligned
	if ( (void*)bfr + 1 <= data_end){
		sum += * ((__u8*) bfr) << 8;
	}
	while( sum >> 16 > 0) {
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
	return (__u16) ~sum;
}

static int forward_ip_traffic(void* data, void* data_end, struct ethhdr* ether_header){
	struct iphdr* iphdr = (struct iphdr*) data_pointer_at(data, data_end, ETH_HDR_SIZE, IP_HDR_SIZE);
	if (iphdr == NULL) {
		return XDP_DROP;
	}
	if (iphdr->protocol != UDP_PROT) {
		static const char fmt[] = "Only UDP communication is currently supported";
		bpf_trace_printk(fmt, sizeof(fmt));
		return XDP_DROP;
	}
	struct udphdr* udp_header = (struct udphdr*) data_pointer_at(data, data_end, ETH_HDR_SIZE + IP_HDR_SIZE, sizeof(struct udphdr));
	if ( udp_header == NULL ) {
		return XDP_DROP;
	}
	
	iphdr->check = 0;
	iphdr->check = ip_checksum((__u16*)iphdr, IP_HDR_SIZE);
	udp_header->check = 0;
	udp_header->check = udp_checksum(udp_header, iphdr, data_end);
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

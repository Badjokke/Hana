#pragma once
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#define MAX_PAYLOAD_SIZE 1480
static __u16 ip_checksum(struct iphdr* iphdr, int count) {
	iphdr->check = 0;
	__u16* bfr = (__u16*) iphdr;
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

static __u32 pseudoheader_checksum(struct iphdr* iphdr) {
	__u32 sum = 0;
	sum += (__u16)iphdr->saddr;
	sum += (__u16)(iphdr->saddr >> 16);
	sum += (__u16)iphdr->daddr;
	sum += (__u16)(iphdr->daddr >> 16);
	sum += (__u16)iphdr->protocol << 8;
	return sum;
}

static __u16 udp_checksum(struct udphdr* udphdr, struct iphdr* iphdr, void* data_end){
	udphdr->check = 0;
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
       if ( (__u8*)bfr + 1 <= (__u8*)data_end){
               sum += * ((__u8*) bfr) << 8;
       }
       while( sum >> 16 > 0) {
               sum = (sum >> 16) + (sum & 0xFFFF);
       }
       return (__u16) ~sum;
}


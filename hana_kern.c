#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int balancer(struct xdp_md* ctx){

	return XDP_PASS;
}
SEC("license") char* licence = "GPL\0";

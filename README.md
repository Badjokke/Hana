# Hana - eBPF powered load balancer
Hana is built on top of [ebpf](https://docs.ebpf.io/) and can be used as a load balancer for UDP communication. Just like [katran](https://github.com/facebookincubator/katran), Hana
uses DSR (Direct Service Return) architecture and requires a bit of a configuration regarding virtual IP and ARP. Hana is a combination of user space and XDP (kernel) program.  
User space part of Hana is built using [Cilium's ebpf-go](https://github.com/cilium/ebpf). This process is responsible for attaching the XDP program to a network interface,
periodically polling health of the configured nodes and writing / deleting into the BPF maps. XDP program only reads them.
## Build and run
```sh
go generate
go build
./hana-ebpf ./properties/properties.yaml
```
## Configuration
IPv6 is currently not supported. The properties file is read from the user space application. `nodes` are inserted into bpf map if they are healthy.
```yaml
nodes:
  - node:
      ip_addr: "192.168.1.103"
      mac_addr: "a0:ad:9f:bc:13:5a"
healthcheck:
  port: 9001
  message: "health"
  response: "HELLO_FROM_SERVER"
network_interface: "wlo1"
```

## Broad network view
Figure below show very broad overview of network flow. There must be a entry in the `arp table` for every backend node in the configuration.
The backend nodes should reject arp communication from the internet and only accept it from the load balancing node.
![Broad overview](./figs/hana_broad.svg)
## Process view
The diagram below shows a more detailed component view and communication between user-space and kernel-space program.
![Detailed view](./figs/hana_detailed.svg)

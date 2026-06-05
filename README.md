# Hana - L4 load balancer
Simple L4 load balancer which forwards traffec to nodes specified in the configuration, more in [configuration section](#Configuration).  
Unlike Meta's [katran](https://github.com/facebookincubator/katran) this implementation does not use Direct Service Response. The client and the server communicate through the load balancer. 
To achieve this indirect communication, the XDP load balancer uses ephemeral source ports for the requests. The target server has to respond to the same port to correctly pair the req/response pair.
```
                         key = target_node_ip^ephemeral_port; the key is used as a hash to store the original client's ip info = {source_addr, source_port}
                                   ^-----------^--------------------
                                                              |    |
[ CLIENT MACHINE ] ---{source_addr, source_port}--->[XPD]---{target_node_ip, ephemeral_port}--->[TARGET SERVER]
                                                                ^
                                                                |
                                                                |
                                                            dest_addr = ip of the server
                                                            ephemeral_port = ephemeral port generated (goes from X to 2^16 and then wraps around back to X)

```
The backward pass is basically the same regarding the ip information - `source_addr` and `source_port` from the `[TARGET SERVER]` will be used to compute the `key`.  
The data type of Map is [LRU](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_LRU_HASH/). If no stored data are found under the `key`, the communication is dropped. 
Hana forwards `TCP` and `UDP` traffic directly bypassing the kernel (avoids `sockbuf` allocation). For any other protocol the packet is passed to the kernel stack.

# Configuration
Below is a sample configuration in yaml which is understood by the userspace program and loaded on start of the application.
If the file read or parsing to yaml fails, program panics.
```yaml
# list of target nodes which will be used - nodes are selected randomly from kernel program
nodes:
  - node:
        # ipv4 address - replace with your target server
      ip_addr: "10.0.0.2"
        # port to which all the TCP/UDP traffic will be forwarded to
      port: 8000
        # mac address of the network device on the destination host
      mac_addr: "00:e0:4c:bb:ca:1d"
  - node:
      ip_addr: "10.0.0.3"
      port: 8000
      mac_addr: "00:e0:4c:bb:ca:1d"
        # network interface on load balancer device to which the XDP program will bind to
network_interface: "lo"
```

# Dependencies
The kernel core is built on top of [EBPF](https://ebpf.io/) which is shipped by default with linux kernel.  
The userspace program is currently build on top of cillium's ebpf library written in pure Go. [Check them out](https://github.com/cilium/ebpf).


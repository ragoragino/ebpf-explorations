**A look at container networking from the kernel with eBPF**

**Intro** \
Few weeks ago, I have started to fiddle around with the eBPF project and tracing Linux kernel functions. I have written a simple ICMP packet tracer to just get a feel how the eBPF works. During that project, I noticed that in one function I was tracing on the ingress packet path (called ip_rcv) there are mentions of a network namespace. It is understandable that network namespace must be somehow handled inside the kernel, but I have never had any specific idea how is namespacing accomplished there. So I thought that it might be a fun exercise to understand container networking (that is built on top of Linux network namespaces) from a kernel perspective with the help of eBPF. So my idea was to put traces on several places inside selected kernel networking routines to track how does ingress and egress traffic of a container (for simplicity I have chosen a Docker container) work. I have limited the scope of packets to just sending one ping request and receiving a reply (aka ICMP Echo Request and Echo Reply), but I think the logic is easily generalizable to other transport and application protocols.

**Docker networking** \
Firstly, we should discuss how a Docker container networking works on a higher-level. You probably know that container technology is based on Linux namespaces and cgroups. Namespaces (like network, user, process, mount, uts etc.) allow separation between how the host and how the container view the state of the system. Cgroups provide a way to limit access to hardware resources (i.e. no container can spawn huge amount of processes that will take over the CPU). From a networking perspective, the most important container element is a network namespace that provides container with a completely separete stack of network interfaces, routes and firewall rules. However, by default, processes running inside a network namespace are completely cut-off from the outside - nobody can reach it from the outside and it cannot send any request either. There are several ways how containers can break out of this isolation. 

In the Docker world, there are two other networking modes (besides this none mode, where the container is fully isolated) and these are host and bridge. In the host mode, the networking namespace is not created and the processes in the container share the same network stack as the host. The usage of this mode might be for high-performance applications (we will see why later) or for debugging (turn on host network mode in managed K8S clusters where SSH access to the nodes is not trivial, e.g. for a quick packet analysis via tcpdump of the host traffic). The bridge mode is the default mode for container networking. It provides external access to the world, but prohibits any new (i.e. not a communication of an already established channels) traffic to the container.

At the center of the bridge mode is a bridge interface, veth pairs and iptables. Bridge is an L2 device that acts like a virtual network switch, i.e. it connects multiple L2 segments. However, it can also serve as a default gateway for a group of interfaces (either virtual, like NICs inside containers, or physical interface), in which case it also has an IP address.[^bridge] Upon starting, Docker creates a virtual bridge that can be spotted in the output of an ip address command:

```console
$ ip address
...
4: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:36:a3:02:17 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:36ff:fea3:217/64 scope link 
       valid_lft forever preferred_lft forever
...
```

Docker by default assigns an IP address to the bridge (172.17.0.1) and reserves a subnet 172.17.0.0/16 to be used by containers. This subnet is automatically added to the routing table of the kernel that now knows that any traffic to that subnet should be routed to the docker0 bridge interface:

```console
$ ip route
default via 192.168.0.1 dev wlo1 proto dhcp metric 600 
169.254.0.0/16 dev wlo1 scope link metric 1000 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 
192.168.0.0/24 dev wlo1 proto kernel scope link src 192.168.0.10 metric 600 
```

After creating a new container in a bridge mode, besides a default loopback interface, the container is assigned an eth0 interface in the container network namespace. This eth0 interface is then connected to the bridge (that exists in the default network namespace) with a so-called veth pair. Veth pair is just like an Ethernet cable whose one side is plugged inside the container and the other side is plugged in a port in the bridge. Docker then assigns an IP address from the reserved subnet to the eth0 NIC and also points a container's default gateway to the bridge IP address. We can check this by running ip commands from inside a container:

```console
$ ip address
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
19: eth0@if20: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

As we can see, container was assigned an eth0 interface with an IPv4 address of 172.17.0.2 and has a default gateway at 172.17.0.1 (that can be access via eth0) which is the IP address of the docker0 bridge. It also knows that it can access any address inside the subnet 172.17.0.0/16 (which will host all Docker containers) directly on an L2 (virtual) segment.

A similar summary can be also obtained with native Docker commands:

```console
$ docker network inspect bridge
[
    {
        "Name": "bridge",
        "Id": "e8a1afe73718fd60fe6b5f0a76d65d83ee6ab1829c93d2a86833082e09b9f69b",
        "Created": "2021-04-01T21:48:17.639033352+02:00",
        "Scope": "local",
        "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": null,
            "Config": [
                {
                    "Subnet": "172.17.0.0/16",
                    "Gateway": "172.17.0.1"
                }
            ]
        },
        "Internal": false,
        "Attachable": false,
        "Ingress": false,
        "ConfigFrom": {
            "Network": ""
        },
        "ConfigOnly": false,
        "Containers": {
            "863be8621a0cb3b11ee5c62768493c647142b038a88d8702096983831852465f": {
                "Name": "sleepy_mirzakhani",
                "EndpointID": "63a919c6849791bd20afb2d2874356126570816e780d3bdfb3c3ca603350ece0",
                "MacAddress": "02:42:ac:11:00:02",
                "IPv4Address": "172.17.0.2/16",
                "IPv6Address": ""
            }
        },
        "Options": {
            "com.docker.network.bridge.default_bridge": "true",
            "com.docker.network.bridge.enable_icc": "true",
            "com.docker.network.bridge.enable_ip_masquerade": "true",
            "com.docker.network.bridge.host_binding_ipv4": "0.0.0.0",
            "com.docker.network.bridge.name": "docker0",
            "com.docker.network.driver.mtu": "1500"
        },
        "Labels": {}
    }
]
```

Even though we see how a communication between containers and from containers to default network namespace (host) is achieved, how a communication of containers with outside world is established? This is where iptables come into play. Docker by default establishes several IP tables rules, mainly in the nat and filter tables. For outbound traffic, there needs to be firstly a rule that will forward the traffic from the docker0 bridge to the outside world. This is specified in the filter table and forward chain (rule 5):


```console
$ iptables --table filter --list -v
...
Chain FORWARD (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1      165 12272 DOCKER-USER  all  --  any    any     anywhere             anywhere            
2      165 12272 DOCKER-ISOLATION-STAGE-1  all  --  any    any     anywhere             anywhere            
3       76  6048 ACCEPT     all  --  any    docker0  anywhere             anywhere             ctstate RELATED,ESTABLISHED
4        0     0 DOCKER     all  --  any    docker0  anywhere             anywhere            
5       89  6224 ACCEPT     all  --  docker0 !docker0  anywhere             anywhere            
6        0     0 ACCEPT     all  --  docker0 docker0  anywhere             anywhere            
...
```
In addition, Docker needs to setup a SNAT as the container is inside an internal network. Therefore, in the postrouting chain a rule with a MASQUERADE target is applied to hide Docker internal IP range behind a dynamic IP address of the outbound interface (wlo1 in my case):

```console
$ iptables --table nat --list -v
...
Chain POSTROUTING (policy ACCEPT 39577 packets, 2951K bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1       42  2744 MASQUERADE  all  --  any    !docker0  172.17.0.0/16        anywhere            
...
```

For the inbound traffic Docker will need to setup a rule to translate the destination IP of the packet to the source IP of the process inside the container that is waiting for the response. This is achieved with a connection tracking table rule (rule 3): 

```console
$ iptables --table filter --list -v
...
Chain FORWARD (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1      165 12272 DOCKER-USER  all  --  any    any     anywhere             anywhere            
2      165 12272 DOCKER-ISOLATION-STAGE-1  all  --  any    any     anywhere             anywhere            
3       76  6048 ACCEPT     all  --  any    docker0  anywhere             anywhere             ctstate RELATED,ESTABLISHED
4        0     0 DOCKER     all  --  any    docker0  anywhere             anywhere            
5       89  6224 ACCEPT     all  --  docker0 !docker0  anywhere             anywhere            
6        0     0 ACCEPT     all  --  docker0 docker0  anywhere             anywhere            
...
```

[TODO: Create a picture of how the veth pair + bridge looks like]

These changes in the iptables rules should allow the traffic to flow from the container to the world and back. Allowing new traffic to the container can be also done, however, for the reasons of simplicity I won't pursue that here. So let's summarize the path inbound and outbound connection to the outside world will have to travel when moving through the networking stacks on the machine. 

A process in a container sends a network packet (let's say it pings an hrw.org), which firstly goes through the container namespace stack. As the default route out of the container is to the network bridge interface docker0 (via the veth pair), the packet will move there. On docker0, an input packet processing is started and the kernel will push the packet to the forwarding path as the packet is not destined to the host itself. In the forward path, a FORWARD netfilter chain will be applied and the packet is accepted as its conditions match the FORWARD rule installed by Docker. The packet is then pushed to the egress path of the kernel, where a POSTROUTING netfiler chain is applied. Here the packet will have its source IP and port changed as the MASQUERADE rule is matched. Afterward, the packet is sent to the default gateway. When a response is received by the host NIC, an input processing on the host is invoked. A real destination route of the packet is obtained from the connection tracking table and the IP header is changed accordingly. As the packet is not meant for the host but for the Docker subnet that is accessible via the Docker bridge (as specified in the kernel routing table), the packet is forwarded to the Docker bridge. Another FORWARD rule installed by Docker accepts the packet and moves it to the egress chain on the docker0 interface. Here, the packet is just forwarded to the proper container via the veth pair, where an ingress path is initiated and the packet is delivered to the local ping process that initiated the request in the first place.

**Kernel network namespaces** \
Okay, so now we should have a clear picture what is the path of the packet through the kernel. So let's the go through the kernel code itself that lies on that path so we see where we could insert our eBPF traces to verify the packet's route. The three most interesting parts for us are ingress path, forward path and egress path. We encounter the traffic on the ingress path three times - for the outbound traffic, the ingress path is invoked when the docker0 bridge receives the packet from the container and on the outbound traffic it is invoked once when the packet arrives on the host and then when the packet arrives to the container. When the packet arrives on the host it also undergoes connection tracking translation of the destination IP address due to the NAT. The forward path is executed twice, for the outbound traffic when the packet is received by the docker0 bridge and forwarded to the host default gateway (i.e. outside the machine) and for the inbound traffic after the NAT occurs and the traffic needs to be forwarded to the docker0 bridge. The egress path is invoked three times, during the outbound traffic when the container sends the packet to the virtual veth pair, and then when the traffic undergoes SNAT and leaves the host, and on the inbound path when the traffic is leaving to the docker0 interface. 

[TODO: Create a picture of the travel in the kernel, i.e. from the study]

**eBPF traces** \
So, based on this packet journey, I thought that it would be most useful to see the packet arriving on the IP stack, then being NATted (for the inbound traffic), then somewhere on the forward path and then egress paths also with the NAT. So together, we could insert 5 kernel traces to detect ingress, ingress after reverse NAT, forward, egress, egress after NAT points. There is a large number of possibilities where to insert kernel probes in order to obtain these traces, however I have decided to trace the following functions: entry to ip_rcv, exit of ip_rcv_core, entry to ip_forward_finish, entry to ip_output and exit of dev_queue_xmit respectively. TODO: Explain why? [^kernel_flow]

The most interesting information that can be exported from the kernel trace will be IP protocol, source and destination, MAC source and destionation, name of the network interface, pid, tgid and name of the process under which the OS handlers are running and the inode number of the network namespace. I won't go into details of the eBPF program, as I have already written about that in a previous blog post.[^ebpf] 

So after starting a testing Docker container, and pinging some remote address (like google.com) from inside of that container, I have recorded two sets of traces, one for egress path (requesT) and one for ingress path (reply). So, let's parse the egress traffic first:

```console
EGRESS; Timestamp: 83154125743740; PID: 27806; TID: 27806; Inode: 4026532334; Name: b'ping'; Source: 172.17.0.2; Destination: 172.217.23.238; Protocol: 1; DeviceName: b''; SrcMac: ; DestMac: 80:05:88:9B:1C:01
EGRESS_AFTER_NAT; Timestamp: 83154125759324; PID: 27806; TID: 27806; Inode: 4026532334; Name: b'ping'; Source: 172.17.0.2; Destination: 172.217.23.238; Protocol: 1; DeviceName: b'eth0'; SrcMac: ; DestMac: 80:05:88:9B:1C:01
INGRESS; Timestamp: 83154125792897; PID: 27806; TID: 27806; Inode: 475981928; Name: b'ping'; ; Source: 172.17.0.2; Destination: 172.217.23.238; Protocol: 1; DeviceName: b'docker0'; SrcMac: 02:42:AC:11; DestMac: 02:42:36:A3:02:17
INGRESS_AFTER_NAT; Timestamp: 83154125803267; PID: 27806; TID: 27806; Inode: 4026531992; Name: b'ping'; Source: 172.17.0.2; Destination: 172.217.23.238; Protocol: 1; DeviceName: b'docker0'; SrcMac: 02:42:AC:11; DestMac: 02:42:36:A3:02:17
FORWARD; Timestamp: 83154125811464; PID: 27806; TID: 27806; Inode: 4026531992; Name: b'ping'; Source: 172.17.0.2; Destination: 172.217.23.238; Protocol: 1; DeviceName: b'docker0'; SrcMac: 02:42:AC:11; DestMac: 02:42:36:A3:02:17
EGRESS; Timestamp: 83154125816190; PID: 27806; TID: 27806; Inode: 4026531992; Name: b'ping'; Source: 172.17.0.2; Destination: 172.217.23.238; Protocol: 1; DeviceName: b'docker0'; SrcMac: 02:42:AC:11; DestMac: 02:42:36:A3:02:17
EGRESS_AFTER_NAT; Timestamp: 83154125829651; PID: 27806; TID: 27806; Inode: 4026531992; Name: b'ping'; Source: 192.168.0.10; Destination: 172.217.23.238; Protocol: 1; DeviceName: b'wlo1'; SrcMac: D0:DF:9A:95:34:13; DestMac: 54:67:51:DC:A1:DC
```

For all traces we can see that they happen under a process ping and they trace the ICMP protocol. The flow starts with leaving the container, and we can see two traces, and because NAT is not executed at this stage, they are almost identical. We can see the IP source addresses being the IP address of the container (TODO: why no srcmac + devicename), while the destintation IP address is the address of the resolved google.com. The inode number corresponds to the container inode number and this can be verified by checking the procfs record corresponding to the process with PID 1 in the container (in my case default PID of this process is 11005):

```console
$ sudo ls -l /proc/11005/ns/net
lrwxrwxrwx 1 root root 0 dub  4 17:39 /proc/11005/ns/net -> 'net:[4026532334]'
```
At the end of the line we can see 4026532334 which corresponding to the inode number in the kernel traces. [TODO: Why the MAC address?] After the packet is routed from the container interface, we can see that it is received by the docker0 interface. We can see that source and destination MAC addresses correspond to the MAC address of the eth0 interface inside the container and the MAC address of the docker0 interface. We can see a change in the inode number, which corresponds to the inode [TODO]. The destination route of the traffic is then resolved by the kernel and because the traffic is not destined to the local machine, it is forwarded, which can be seen in the trace originating from a forwarding routine. We can already notice that the inode number changes to 4026531992 which corresponds to the default network namespace inode number:

```console
$ sudo ls -l /proc/1/ns/net
lrwxrwxrwx 1 root root 0 dub  4 17:49 /proc/1/ns/net -> 'net:[4026531992]'
```

After that point, we can see the egress path being initiated, with NAT being performed here. We can see that the source IP and MAC are changed to the IP and MAC addresses of the host (192.168.0.10, D0:DF:9A:95:34:13), while the destination MAC is the MAC of the default gateway.

Okay, so this was the egress traffic and what happens when the reply from google.com arrives. This is how the trace looks like after reordering based on the timestamp:

```console
INGRESS; Timestamp: 83154158404366; PID: 0; TID: 0; Inode: 475981928; Name: b'swapper/1'; ; Source: 172.217.23.238; Destination: 192.168.0.10; Protocol: 1; DeviceName: b'wlo1'; SrcMac: 54:67:51:DC:A1:DC; DestMac: D0:DF:9A:95:34:13
INGRESS_AFTER_NAT; Timestamp: 83154158491135; PID: 0; TID: 0; Inode: 4026531992; Name: b'swapper/1'; Source: 172.217.23.238; Destination: 172.17.0.2; Protocol: 1; DeviceName: b'wlo1'; SrcMac: 54:67:51:DC:A1:DC; DestMac: D0:DF:9A:95:34:13
FORWARD; Timestamp: 83154158514073; PID: 0; TID: 0; Inode: 4026531992; Name: b'swapper/1'; Source: 172.217.23.238; Destination: 172.17.0.2; Protocol: 1; DeviceName: b'wlo1'; SrcMac: 54:67:51:DC:A1:DC; DestMac: D0:DF:9A:95:34:13
EGRESS; Timestamp: 83154158526096; PID: 0; TID: 0; Inode: 4026531992; Name: b'swapper/1'; Source: 172.217.23.238; Destination: 172.17.0.2; Protocol: 1; DeviceName: b'wlo1'; SrcMac: 54:67:51:DC:A1:DC; DestMac: D0:DF:9A:95:34:13
EGRESS_AFTER_NAT; Timestamp: 83154158554311; PID: 0; TID: 0; Inode: 4026531992; Name: b'swapper/1'; Source: 172.217.23.238; Destination: 172.17.0.2; Protocol: 1; DeviceName: b'docker0'; SrcMac: 02:42:36:A3:02:17; DestMac: 02:42:AC:11
INGRESS; Timestamp: 83154158626943; PID: 18; TID: 18; Inode: 0; Name: b'ksoftirqd/1'; ; Source: 172.217.23.238; Destination: 172.17.0.2; Protocol: 1; DeviceName: b'eth0'; SrcMac: 02:42:36:A3:02:17; DestMac: 02:42:AC:11
INGRESS_AFTER_NAT; Timestamp: 83154158649956; PID: 18; TID: 18; Inode: 4026532334; Name: b'ksoftirqd/1'; Source: 172.217.23.238; Destination: 172.17.0.2; Protocol: 1; DeviceName: b'eth0'; SrcMac: 02:42:36:A3:02:17; DestMac: 02:42:AC:11
```

The ingress path is invoked and we can see that the process handling that packet is a so-called swapper process with PID 0. [TODO: Describe swapper]. We can see that the source and destination IP and MAC addresses are identical to the ones that were sent in the last record of the egress flow, just reversed. After the packet is received by the IP network stack, a connection tracking table is consulted and a destination IP is changed to the IP address of the container. [^icmp_nat] Because the packet is not destined to the local host, it is forwarded and pushed to the egress path on the docker0 interface. Here, again we can notice that before the packet leaves the docker0 interface, the source and and destination MAC addresses are set to the addresses of the network bridge interface and container respectively. At the end, packet is received by the kernel's ingress processing in the container namespace and finally delivered to the ping process.

**End** \
This probably has been pretty exhausting journey (not just for you), so I will stop here! The whole process can get pretty convoluted when we are really delving into the depths of the kernel network stack, and I am sure, I have made several factual and logical mistakes. So please, don't hesitate to write me, if you will notice some. If you liked the program and you would like to check the source code for this example, header over to: <>.

Otherwise, I have found a not-so-different endeavour (although with quite different kernel probes) that was done here: <https://blog.yadutaf.fr/2017/07/28/tracing-a-packet-journey-using-linux-tracepoints-perf-ebpf/>, so if you are interested, you can check it out.

Otherwise, a good resource for layer 3 kernel flow can be found here: https://wiki.aalto.fi/download/attachments/70789059/linux-kernel-ip.pdf. Here is a fine description of the communication from and to network namespaces done from the bottom up: <https://helda.helsinki.fi/bitstream/handle/10138/320475/Viding_Jasu_DemystifyingContainerNetworking_2020.pdf>.

Some other good resources about container networking or IPtables:
<https://rancher.com/learning-paths/introduction-to-container-networking>
<https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture>
<https://woosley.github.io/2017/07/25/understand-docker-iptables-rules.html>


Footnotes:

[^bridge]: <https://unix.stackexchange.com/questions/319979/why-assign-mac-and-ip-addresses-on-bridge-interface>
[^kernel_flow]: <https://wiki.linuxfoundation.org/networking/kernel_flow> and <https://wiki.aalto.fi/download/attachments/70789059/linux-kernel-ip.pdf>
[^ebpf]:
[^icmp_nat]: <https://superuser.com/questions/135094/how-does-a-nat-server-forward-ping-icmp-echo-reply-packets-to-users>
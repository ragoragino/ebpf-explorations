In the last few days I have started digging into the extended Barkeley Packet Filters (eBPFs). I have found out about this technologu when I was 
learning about the internal workings of tcpdump (see https://blog.cloudflare.com/bpf-the-forgotten-bytecode/). 
tcpdump works by attaching a filter during the creation of the socket, which causes all network packets to be also routed to this 
filter. Kernel requires these filters to be passed in the form of a BPF bytecode, which is a specific bytecode that can execute only a restricted set of operations. The reason kernel allows only a pre-specified instruction set is to remove potential security vectors associated with running userspace programs 
inside kernel. The bytecode is after verification either executed by the BPF interpreter running in the kernel or JIT compiled to the native code. The filter
is always called when a new packet arrives and passes interesting packets to the userspace via a file descriptor. 

Kernel developers spotted a huge potential that this type of kernelspace - userspace communication could provide to the larger community
and hence extended BPF was born. eBPF is not only a packet filter, but provides a very generic hardware, kernel, and userspace tracing and monitoring
functionalities. One can attach a BPF program to almost all kernel functions (that are non-inlined), user functions, hardware counters and a lot more.
It is a pretty powerful beast and there has been of traction behind it lately. A major architecture difference between classical and extended BPF 
is that the extended version's bytecode is 64bit and has a larger instruction set. Additional improvements in the interaction with the kernel include a decent amount of data structures that are shared between kernel and userspace.

Even though it might sound like eBPF is the best, there are still some limits to its power. Debugging of BPF programs can be pretty cumbersome,
the majority of kernel calls are not API-stable, and one cannot change the function arguments for the most part (except some networking program
types like XDP and tc, which can modify network traffic, see this article for a simple UDP traffic port redirection:
https://duo.com/labs/tech-notes/writing-an-xdp-network-filter-with-ebpf, or https://mcorbin.fr/pages/xdp-introduction/ for a networking filter). 

I wanted to get my hands dirty by trying to write a simple eBPF program. There is a couple of options how to do it. One is to 
directly pass BPF compiled object file to the bpf syscall (or command line tools using the bpf syscall like tc). However, there is a very convenient wrapper called bcc that allows users to develop new eBPF programs without a lot of hassle and it has a pretty neat binding in Python. So I just installed and compiled bcc framework (https://github.com/iovisor/bcc/blob/master/INSTALL.md). Before installing, one just needs to check that the kernel version was compiled with all the necessary flags for running eBPF programs (https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration).

On the bcc Github page, they host a couple of examples and tools one can use as an inspiration. I just wanted to create a simple showcase,
so I thought I could trace ping calls on my machine. I would initiate a ping request from another machine on my LAN
(or using Python's scapy package on the same machine), and trace those requests on the target machine running an eBPF program. 

[TODO: Description of the program]

By running this, I was able to see ICMP Echo Requests (aka ping) requests arriving on the network interface:

`Source: 192.168.0.115; Destination: 192.168.0.10; Protocol: 1` (protocol 1 is the ICMP protocol)

By further checking the Linux kernel's IP stack during development of these tracers, I saw that the function ip_rcv calls an NF_HOOK 
(https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L531). This actually calls netfiler's own NF_INET_PRE_ROUTING chain before calling
the ip_finish in case of success. In case the packet is dropped, the ip_finish is not called. So I thought that I might also try tracing the ICMP 
echo-request packets that were dropped by the netfilter. It seems that the NF_FILTER returns -EPERM in case a packet is dropped so I started
checking return value from ip_rcv (https://github.com/torvalds/linux/blob/master/net/netfilter/core.c). As this is only a quick example, I did not bother
with verifying whether ip_rcv_finish, which is called after the netfiler hook and before ip_rcv returns in case netfiler does not drop the packet,
cannot also return the same value. So I just disabled ICMP Echo Request in iptables by executing: `sudo iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT` and then started pinging my target machine. I could see the packets being dropped:

`Source: 192.168.0.115; Destination: 192.168.0.10; Protocol: 1; Drop; 1`

I also wanted to check whether I could trace an inner function of ip_rcv that returns just the parsed socket buffer (function called ip_rcv_core).
However, I found out that bcc failed to attach this kprobe with an error message "Failed to attach BPF to kprobe". It seemed like this function name did not exist, so I checked kernel's system map and found out that there was no ip_rcv_core, but indeed there was ip_rcv_core.isra.20 present. After a quick google search, I found out that gcc compiler can mangle function names when doing optimizations (for an explation see this https://stackoverflow.com/questions/18907580/what-is-isra-in-the-kernel-thread-dump/18914402#18914402, see also https://github.com/iovisor/bcc/issues/1754 for a discussion on bcc github issues page). So after replacing the argument to attach_kretprobe I was able to trace ip_rcv_core also. This had an advantage over the previous version because
I didn't need to use any hash map to track the process and thread ids between the kprobe and kretprobe as I just needed a single kretprobe.
However, ip_rcv_core is run just before netfiler, so it's not possible to track netfiler's packet drops by this trace.

So this is all for today. Stay safe.

More about kprobe and kretprobe, see: https://www.kernel.org/doc/Documentation/kprobes.txt
An article about the internal workings of tcpdump: https://blog.cloudflare.com/bpf-the-forgotten-bytecode/ 
A presentation about classical and extended BPF: https://qmo.fr/docs/talk_20190516_allout_programmability_bpf.pdf
Packet's journey through Linux stack:
    https://www.privateinternetaccess.com/blog/linux-networking-stack-from-the-ground-up-part-1/ (this is just brutal)
    https://epickrram.blogspot.com/2016/05/navigating-linux-kernel-network-stack_18.html (this is more brain-friendly)
In the last few days I have started digging into the extended Barkeley Packet Filters (eBPFs). I have found out about this technologu during 
learning about the internal workings of tcpdump (see https://blog.cloudflare.com/bpf-the-forgotten-bytecode/). 
tcpdump works by attaching a specific filter (with specific options) on the Linux socket API, which causes all network packets to be also routed to this 
filter. Kernel requires these filters to be passed in the form of a BPF bytecode, which is a specific bytecode that forbids certain operations. 
The reason kernel allows only a pre-specified instruction set is to remove potential security issues associated with running userspace programs 
inside kernel (like freezing or crashing). The bytecode is after verification executed by the BPF interpreter running in the kernel. The filter
is always called when a new packet arrives and passes target packets to the user space via a file descriptor. 

Kernel developers spotted a huge potential that this type of kernelspace - userspace communication could provide to the community
and hence extended BPF was born. eBPF is not only a packet filter, but provides a very generic hardware, kernel, and userspace tracing and monitoring
functionalities. One can attach a BPF program to almost all kernel functions (that are non-inlined), user functions, hardware counters and a lot more.
It is a pretty powerful beast and there has been of traction behind it lately. A major architecture difference between classical and extended BPF 
is in the execution of BPF bytecode. Programs run with extended BPF are JIT-compiled to the native code and executed as such, instead of being executed
inside a kernel interpreter.

Even though it might sound like eBPF is the best, there are still some limits to its power. Debugging of BPF programs can be pretty hard,
the majority of kernel calls are not API-stable, and one cannot change the function arguments, so it cannot be used easily as a packet filter
(except XDP and tc subsystems, which can modify network traffic, see this article for a simple UDP traffic redirection:
https://duo.com/labs/tech-notes/writing-an-xdp-network-filter-with-ebpf). 

I wanted to get my hands dirty by trying to write a simple eBPF program. There is a couple of options how to do it. One is to 
work directly with the ebpf library of the linux kernel. **TODO** [XDP, tc] However, there is a very convenient wrapper called bcc that allows users to 
develop new eBPF programs without a lot of hassle. It has a pretty neat binding in Python. So I just installed and compiled bcc framework (https://github.com/iovisor/bcc/blob/master/INSTALL.md).
Before installing, one just needs to check that the kernel version was compiled with all the necessary flags for running eBPF programs (https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration).

On the bcc Github page, they host a couple of neat examples and tools one can use as an inspiration. I just wanted to create a simple example,
so I though I could be tracing ping calls on my machine. I would initiate a ping request from another machine on my LAN, and trace those requests
on the target machine running an eBPF program. 

[TODO: Description of the program]

By running this, I was able to see the ping requests coming on the network interface:

`Source: 192.168.0.115; Destination: 192.168.0.10; Protocol: 1`

By further checking the Linux kernel's IP stack during development of these tracers, I saw that the function ip_rcv returns also an NF_HOOK call
(https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L531). This actually calls netfiler's own NF_INET_PRE_ROUTING before calling
the ip_finish in case of success. In case the packet is dropped, the ip_finish is not called. So I though that I might also try tracing the ICMP 
echo-request packets that were dropped by the nethook filter. It seems that the NF_FILTER returns -EPERM in case a packet is dropped so I started
tracking also those (https://github.com/torvalds/linux/blob/master/net/netfilter/core.c). It might be possible that also ip_rcv_finish (that is called
after the netfiler hook and before ip_rcv returns) could return an identical return value, but I didn't check that any further that possibility. So I 
just disabled ICMP echo-request in iptables by executing: `sudo iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT` and then 
started pinging my target machine. I could see the packets being dropped:

`Source: 192.168.0.115; Destination: 192.168.0.10; Protocol: 1; Drop; 1`

I also wanted to check whether I could trace an inner function of ip_rcv that returns just the parsed socket buffer (function called ip_rcv_core).
However, I found out that bcc failed to attach this kprobe with "Failed to attach BPF to kprobe". It seemed like this function name did not exist,
so I checked kernel's system map and found out that there was no ip_rcv_core, but indeed there was ip_rcv_core.isra.20 present. After a quick google search,
I found out that gcc compiler can mangle function names when doing optimizations (for an explation see this https://stackoverflow.com/questions/18907580/what-is-isra-in-the-kernel-thread-dump/18914402#18914402,
see also https://github.com/iovisor/bcc/issues/1754 for a discussion on bcc github issues page).
So after replacing the argument to attach_kretprobe I was able to trace ip_rcv_core also. This had an advantage over the previous version because
I didn't need to use any hash map to track the process and thread ids between the kprobe and kretprobe as I just needed a single kretprobe.
However, ip_rcv_core is run before netfiler, so it's not possible to track netfiler's packet drops by this trace.

More about kprobe and kretprobe, see: https://www.kernel.org/doc/Documentation/kprobes.txt
An article about the internal workings of tcpdump: https://blog.cloudflare.com/bpf-the-forgotten-bytecode/ 
A presentation about classical and extended BPF: https://qmo.fr/docs/talk_20190516_allout_programmability_bpf.pdf
Packet's journey through Linux stack:
    https://www.privateinternetaccess.com/blog/linux-networking-stack-from-the-ground-up-part-1/ (this is just brutal)
    https://epickrram.blogspot.com/2016/05/navigating-linux-kernel-network-stack_18.html (this is more brain-friendly)
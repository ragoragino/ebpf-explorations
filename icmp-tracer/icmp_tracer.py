from bcc import BPF
from socket import inet_ntop, ntohs, AF_INET
from struct import pack
from time import sleep

# https://epickrram.blogspot.com/2016/05/navigating-linux-kernel-network-stack.html
# https://technical3284.rssing.com/chan-52612767/all_p2.html

# https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c
# https://github.com/iovisor/bcc/blob/master/examples/tracing/tcpv4connect.py

# TODO: How to make this CPU-safe? -> per CPU map?
# https://github.com/iovisor/bcc/issues/1521
program = """
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ip_key_t {
    u32 saddr;
    u32 daddr;
    u16 dport;
};

BPF_HASH(icmp_count, struct ip_key_t);

/* struct pt_regs *ctx exists because it is mantadory to be able to use the parameters of the function*/
int trace_icmp(struct pt_regs *ctx) {
    const struct sk_buff *skb = PT_REGS_RC(ctx);

    const struct iphdr *iph = ip_hdr(skb);
    const u8 protocol = iph->protocol;

    if(protocol == 0x01) {   
        struct ip_key_t key = {};     
        key.saddr = iph->saddr;
        key.daddr = iph->daddr;
        key.dport = ntohs(dport);

        icmp_count.increment(key);
    }

	return 0;
}
"""

b = BPF(text=program)
b.attach_kretprobe(event="ip_rcv", fn_name="trace_icmp")

def depict_cnt(counts_tab):
    for k, v in sorted(counts_tab.items(), key=lambda counts: counts[1].value, reverse=True):
        src_address = inet_ntop(AF_INET, pack('I', k.saddr))
        dest_address = inet_ntop(AF_INET, pack('I', k.daddr)) 
        dest_port = k.dport

        print(f'Source: {src_address}; Destination: {dest_address}; Port: {dest_port}; Value: {v.value}')

print("Tracing ICMP messages ... Hit Ctrl-C to end")
while True:
    try:
        sleep(5)
    except KeyboardInterrupt:
        return

    depict_cnt(b["icmp_count"])

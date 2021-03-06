#include <uapi/linux/ptrace.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct trace_event_data {
    u32 saddr;
    u32 daddr;
    u8 protocol;
};

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

BPF_PERF_OUTPUT(events);

int ip_rcv_core_exit(struct pt_regs *ctx) {
	const struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);
	if (skb == 0) {
		return 0;	// ip_rcv_core failed
	}

    const struct iphdr *iph = skb_to_iphdr(skb);

    if(iph->protocol == 0x01) {
        struct trace_event_data data = {};     
        data.saddr = iph->saddr;
        data.daddr = iph->daddr;
        data.protocol = iph->protocol;

        events.perf_submit(ctx, &data, sizeof(data));
    }  

	return 0;
}

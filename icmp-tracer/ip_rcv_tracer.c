#include <uapi/linux/ptrace.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct trace_event_data {
    u32 saddr;
    u32 daddr;
    u8 protocol;
	u8 nf_dropped;
};

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

BPF_HASH(currsock, u32, struct sk_buff *);

BPF_PERF_OUTPUT(events);

int ip_rcv_enter(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	u32 pid = bpf_get_current_pid_tgid();
	currsock.update(&pid, &skb);
	return 0;
};

int ip_rcv_exit(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();
	struct sk_buff **skbp;
	skbp = currsock.lookup(&pid);
	if (skbp == 0) {
		return 0;	// missed entry
	}

	if (ret != 0 && ret != -EPERM) {
		currsock.delete(&pid);
	    return 0;
	}

	struct sk_buff *skb = *skbp;

    const struct iphdr *iph = skb_to_iphdr(skb);

    if(iph->protocol == 0x01) {
        struct trace_event_data data = {};     
        data.saddr = iph->saddr;
        data.daddr = iph->daddr;
        data.protocol = iph->protocol;
		data.nf_dropped = ret == -EPERM;

        events.perf_submit(ctx, &data, sizeof(data));
    }

	return 0;
}
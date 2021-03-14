#include <uapi/linux/ip.h>
#include <linux/pid_namespace.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct trace_event_data {
    u32 saddr;
    u32 daddr;
    u8 protocol;
    u32 proc_inode_numer;
    u32 pid;
    u32 tgid;
};

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

BPF_HASH(currdev, u32, struct net *);

BPF_PERF_OUTPUT(ingress);

int ip_rcv_core_entry(struct pt_regs *ctx, struct sk_buff *skb, struct net *net) 
{
    u32 tid = bpf_get_current_pid_tgid();
    currdev.update(&tid, &net);
    return 0;
}

int ip_rcv_core_exit(struct pt_regs *ctx) {
	const struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);
	if (skb == 0) {
		return 0;	// ip_rcv_core failed
	}

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;

    struct net **netp;
    netp = currdev.lookup(&tid);
    if (netp == 0) {
        return 0;   // missed entry
    }

    currdev.delete(&tid);
    
    const struct iphdr *iph = skb_to_iphdr(skb);
    struct net *net = *netp;

    struct trace_event_data data = {};     
    data.saddr = iph->saddr;
    data.daddr = iph->daddr;
    data.protocol = iph->protocol;
    data.proc_inode_numer = net->ns.inum;
    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    ingress.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

BPF_PERF_OUTPUT(egress);

int ip_local_out_entry(struct pt_regs *ctx, struct net *net, struct socket *sk, 
    struct sk_buff *skb) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    const struct iphdr *iph = skb_to_iphdr(skb);

    struct trace_event_data data = {};     
    data.saddr = iph->saddr;
    data.daddr = iph->daddr;
    data.protocol = iph->protocol;
    data.proc_inode_numer = net->ns.inum;
    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    egress.perf_submit(ctx, &data, sizeof(data));

	return 0;
}
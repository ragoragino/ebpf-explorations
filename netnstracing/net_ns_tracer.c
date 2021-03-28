#include <uapi/linux/ip.h>
#include <linux/pid_namespace.h>
#include <linux/proc_ns.h>
#include <linux/skbuff.h>
#include <uapi/linux/if.h>
#include <net/net_namespace.h>
#include <net/dst.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct trace_event_data {
    u64 timestamp;
    u32 saddr;
    u32 daddr;
    u8 protocol;
    u32 proc_inode_numer;
    u32 pid;
    u32 tgid;
    char comm[TASK_COMM_LEN];
    char dev_name[IFNAMSIZ];
};

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

static inline struct dst_entry *get_skb_dst(const struct sk_buff *skb)
{
	// unstable API. verify logic in skb_dst in skbuff.h.
	return (struct dst_entry *)(skb->_skb_refdst & SKB_DST_PTRMASK);
}

BPF_HASH(currnet, u32, struct net *);
BPF_HASH(currdev, u32, struct net_device *);

BPF_PERF_OUTPUT(ingress);

int ip_rcv_entry(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev) 
{
    u32 tid = bpf_get_current_pid_tgid();
    currdev.update(&tid, &dev);
    return 0;
}

int ip_rcv_core_entry(struct pt_regs *ctx, struct sk_buff *skb, struct net *net) 
{
    u32 tid = bpf_get_current_pid_tgid();
    currnet.update(&tid, &net);
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
    netp = currnet.lookup(&tid);
    if (netp == 0) {
        return 0;   // missed entry
    }

    currnet.delete(&tid);

    struct net_device **devp;
    devp = currdev.lookup(&tid);
    if (devp == 0) {
        return 0;   // missed entry
    }

    currdev.delete(&tid);
    
    const struct iphdr *iph = skb_to_iphdr(skb);
    struct net *net = *netp;

    struct net_device *dev = *devp;

    struct trace_event_data data = {};   
    data.timestamp = bpf_ktime_get_ns();
    data.saddr = iph->saddr;
    data.daddr = iph->daddr;
    data.protocol = iph->protocol;
    data.proc_inode_numer = net->ns.inum;
    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_kernel(&data.dev_name, sizeof(data.dev_name), (void*)&dev->name);

    ingress.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

BPF_PERF_OUTPUT(egress);

BPF_PERF_OUTPUT(egress_after_nat);

BPF_PERF_OUTPUT(egress_forward);

int ip_local_out_entry(struct pt_regs *ctx, struct net *net, struct socket *sk, 
    struct sk_buff *skb) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    const struct iphdr *iph = skb_to_iphdr(skb);

    struct dst_entry *dst = get_skb_dst(skb);
	struct net_device *dev = dst->dev;

    struct trace_event_data data = {};    
    data.timestamp = bpf_ktime_get_ns(); 
    data.saddr = iph->saddr;
    data.daddr = iph->daddr;
    data.protocol = iph->protocol;
    data.proc_inode_numer = net->ns.inum;
    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_kernel(&data.dev_name, sizeof(data.dev_name), (void*)&dev->name);

    egress.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int ip_finish_output_entry(struct pt_regs *ctx, struct net *net, struct socket *sk, 
    struct sk_buff *skb) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    const struct iphdr *iph = skb_to_iphdr(skb);

    struct dst_entry *dst = get_skb_dst(skb);
	struct net_device *dev = dst->dev;

    struct trace_event_data data = {};     
    data.timestamp = bpf_ktime_get_ns();    
    data.saddr = iph->saddr;
    data.daddr = iph->daddr;
    data.protocol = iph->protocol;
    data.proc_inode_numer = net->ns.inum;
    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_kernel(&data.dev_name, sizeof(data.dev_name), (void*)&dev->name);

    egress_after_nat.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int ip_forward_finish_entry(struct pt_regs *ctx, struct net *net, struct socket *sk, 
    struct sk_buff *skb) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    const struct iphdr *iph = skb_to_iphdr(skb);

    struct dst_entry *dst = get_skb_dst(skb);
	struct net_device *dev = dst->dev;

    struct trace_event_data data = {};     
    data.timestamp = bpf_ktime_get_ns();
    data.saddr = iph->saddr;
    data.daddr = iph->daddr;
    data.protocol = iph->protocol;
    data.proc_inode_numer = net->ns.inum;
    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_kernel(&data.dev_name, sizeof(data.dev_name), (void*)&dev->name);

    egress_forward.perf_submit(ctx, &data, sizeof(data));

	return 0;
}
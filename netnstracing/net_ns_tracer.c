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

struct trace_common_data {
    u64 timestamp;
    u32 proc_inode_numer;
    u32 pid;
    u32 tgid;
    char comm[TASK_COMM_LEN];
};

struct trace_l3_data {
    u32 saddr;
    u32 daddr;
    u8 protocol;
};

struct trace_l2_data {
    char dev_name[IFNAMSIZ];
    unsigned char mac_dest[ETH_ALEN];
    unsigned char mac_src[ETH_ALEN];
};

struct trace_ingress_data {
    struct trace_common_data common;
    struct trace_l2_data l2;
    struct trace_l3_data l3;
};

struct trace_ingress_natted_data {
    struct trace_common_data common;
    struct trace_l2_data l2;
    struct trace_l3_data l3;
};

struct trace_egress_data {
    struct trace_common_data common;
    struct trace_l2_data l2;
    struct trace_l3_data l3;
};

struct trace_egress_natted_data {
    struct trace_common_data common;
    struct trace_l2_data l2;
    struct trace_l3_data l3;
};

struct trace_forward_data {
    struct trace_common_data common;
    struct trace_l2_data l2;
    struct trace_l3_data l3;
};

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

static inline struct ethhdr *skb_to_ethhdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in eth_hdr() -> skb_mac_header().
    return (struct ethhdr *)(skb->head + skb->mac_header);
}

static inline void fill_trace_common_data(const struct iphdr *iph, const struct net *net, struct trace_common_data* data)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    data->timestamp = bpf_ktime_get_ns();
    data->proc_inode_numer = net->ns.inum;
    data->pid = pid_tgid >> 32;
    data->tgid = pid_tgid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

static inline void fill_trace_l3_data(const struct iphdr *iph, struct trace_l3_data* data)
{
    data->saddr = iph->saddr;
    data->daddr = iph->daddr;
    data->protocol = iph->protocol;
}

static inline void fill_trace_l2_data(const struct ethhdr *eth, const struct net_device *dev, struct trace_l2_data *data)
{
    bpf_probe_read_kernel(&data->dev_name, sizeof(data->dev_name), (void*)&dev->name);
    bpf_probe_read_kernel(&data->mac_dest, sizeof(data->mac_dest), (void*)&eth->h_dest);
    bpf_probe_read_kernel(&data->mac_src, sizeof(data->mac_src), (void*)&eth->h_source);
}

// Ingress path

BPF_HASH(ingressnet, u32, struct net *);
BPF_HASH(ingressdev, u32, struct net_device *);

BPF_PERF_OUTPUT(ingress);

int ip_rcv_entry(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
       struct net_device *orig_dev) 
{
    u32 tid = bpf_get_current_pid_tgid();
    ingressdev.update(&tid, &dev);
    return 0;
}

int ip_rcv_core_entry(struct pt_regs *ctx, struct sk_buff *skb, struct net *net) 
{
    u32 tid = bpf_get_current_pid_tgid();
    ingressnet.update(&tid, &net);
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
    netp = ingressnet.lookup(&tid);
    if (netp == 0) {
        return 0;   // missed entry
    }

    ingressnet.delete(&tid);

    struct net_device **devp;
    devp = ingressdev.lookup(&tid);
    if (devp == 0) {
        return 0;   // missed entry
    }

    ingressdev.delete(&tid);
    
    struct net *net = *netp;
    struct net_device *dev = *devp;

    const struct iphdr *iph = skb_to_iphdr(skb);
    const struct ethhdr *eth = skb_to_ethhdr(skb);

    struct trace_ingress_data ingress_data = {};
    fill_trace_common_data(iph, net, &ingress_data.common);
    fill_trace_l2_data(eth, dev, &ingress_data.l2);
    fill_trace_l3_data(iph, &ingress_data.l3);

    ingress.perf_submit(ctx, &ingress_data, sizeof(ingress_data));

    return 0;
}

// Ingress after NAT path
BPF_HASH(ingressnatnet, u32, struct net *);
BPF_HASH(ingressnatskb, u32, struct sk_buff *);

BPF_PERF_OUTPUT(ingress_after_nat);

int ip_rcv_finish_entry(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb) 
{
    u32 tid = bpf_get_current_pid_tgid();
    ingressnatnet.update(&tid, &net);
    ingressnatskb.update(&tid, &skb);
    return 0;
}

int ip_rcv_finish_exit(struct pt_regs *ctx) {
    const int ret = PT_REGS_RC(ctx);
    if (ret == NET_RX_DROP){
        return 0;
    }

    u32 tid = bpf_get_current_pid_tgid();

	struct net **netp;
    netp = ingressnatnet.lookup(&tid);
    if (netp == 0) {
        return 0;   // missed entry
    }

    ingressnatnet.delete(&tid);

    struct sk_buff **skbp;
    skbp = ingressnatskb.lookup(&tid);
    if (skbp == 0) {
        return 0;   // missed entry
    }

    ingressnatskb.delete(&tid);
    
    struct net *net = *netp;
    struct sk_buff *skb = *skbp;

    const struct iphdr *iph = skb_to_iphdr(skb);
    const struct ethhdr *eth = skb_to_ethhdr(skb);
    
    struct net_device *dev = skb->dev;

    struct trace_ingress_natted_data ingress_data = {};
    fill_trace_common_data(iph, net, &ingress_data.common);
    fill_trace_l2_data(eth, dev, &ingress_data.l2);
    fill_trace_l3_data(iph, &ingress_data.l3);

    ingress_after_nat.perf_submit(ctx, &ingress_data, sizeof(ingress_data));

    return 0;
}

// Egress path

BPF_PERF_OUTPUT(egress);

int ip_output_entry(struct pt_regs *ctx, struct net *net, struct socket *sk, 
    struct sk_buff *skb) {
    const struct iphdr *iph = skb_to_iphdr(skb);
    const struct ethhdr *eth = skb_to_ethhdr(skb);

    struct net_device *dev = skb->dev;

    struct trace_egress_data egress_data = {};
    fill_trace_common_data(iph, net, &egress_data.common);
    fill_trace_l2_data(eth, dev, &egress_data.l2);
    fill_trace_l3_data(iph, &egress_data.l3);

    egress.perf_submit(ctx, &egress_data, sizeof(egress_data));

    return 0;
}

// Egress after NAT path

BPF_HASH(egressnet, u32, struct net *);

BPF_PERF_OUTPUT(egress_after_nat);

int ip_finish_output2_entry(struct pt_regs *ctx, struct net *net, struct socket *sk, 
    struct sk_buff *skb) 
{
    u32 tid = bpf_get_current_pid_tgid();
    egressnet.update(&tid, &net);

    return 0;
}

int dev_queue_xmit_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;

    struct net **netp;
    netp = egressnet.lookup(&tid);
    if (netp == 0) {
        return 0;   // missed entry
    }

    egressnet.delete(&tid);

    struct net *net= *netp;

    const struct iphdr *iph = skb_to_iphdr(skb);
    const struct ethhdr *eth = skb_to_ethhdr(skb);

    struct net_device *dev = skb->dev;

    struct trace_egress_natted_data egress_natted_data = {};
    fill_trace_common_data(iph, net, &egress_natted_data.common);
    fill_trace_l2_data(eth, dev, &egress_natted_data.l2);
    fill_trace_l3_data(iph, &egress_natted_data.l3);
    
    egress_after_nat.perf_submit(ctx, &egress_natted_data, sizeof(egress_natted_data));

    return 0;
}

// Forward path

BPF_PERF_OUTPUT(egress_forward);

int ip_forward_finish_entry(struct pt_regs *ctx, struct net *net, struct socket *sk, 
    struct sk_buff *skb) {
    const struct iphdr *iph = skb_to_iphdr(skb);
    const struct ethhdr *eth = skb_to_ethhdr(skb);

    struct net_device *dev = skb->dev;

    struct trace_forward_data forward_data = {};
    fill_trace_common_data(iph, net, &forward_data.common);
    fill_trace_l2_data(eth, dev, &forward_data.l2);
    fill_trace_l3_data(iph, &forward_data.l3);

    egress_forward.perf_submit(ctx, &forward_data, sizeof(forward_data));

    return 0;
}
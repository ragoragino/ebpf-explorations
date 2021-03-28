from bcc import BPF
from socket import inet_ntop, AF_INET
from struct import pack
import os


# Namespace where some kernel threads are running, like swapper
kernel_namespace=3224154216

def log_ingress_event(cpu, data, size):
    event = b["ingress"].event(data)
    log_event("INGRESS", event, default_net_ns_inode_number)


def log_egress_event(cpu, data, size):
    event = b["egress"].event(data)
    log_event("EGRESS", event, default_net_ns_inode_number)


def log_egress_after_nat_event(cpu, data, size):
    event = b["egress_after_nat"].event(data)
    log_event("EGRESS_AFTER_NAT", event, default_net_ns_inode_number)


def log_egress_forward_event(cpu, data, size):
    event = b["egress_forward"].event(data)
    log_event("FORWARD", event, default_net_ns_inode_number)


def log_event(eventType, event, default_net_ns_inode_number):
    # Filter out default namespace traffic and also the internal kernel namespace traffic (swapper and so on)
    if event.proc_inode_numer in (kernel_namespace,):
        return

    src_address = inet_ntop(AF_INET, pack('I', event.saddr))
    dest_address = inet_ntop(AF_INET, pack('I', event.daddr)) 

    print(f'{eventType}; Timestamp: {event.timestamp}; Source: {src_address}; Destination: {dest_address}; Protocol: {event.protocol}; PID: {event.pid}; TID: {event.tgid}; Inode: {event.proc_inode_numer}; Name: {event.comm}; DeviceName: {event.dev_name}')


if __name__ == '__main__':
    print("Running net_ns_tracer.c.")
    b = BPF(src_file="net_ns_tracer.c")
    b.attach_kprobe(event="ip_rcv", fn_name="ip_rcv_entry")
    b.attach_kprobe(event="ip_rcv_core.isra.20", fn_name="ip_rcv_core_entry")
    b.attach_kretprobe(event="ip_rcv_core.isra.20", fn_name="ip_rcv_core_exit")
    b.attach_kprobe(event="ip_local_out", fn_name="ip_local_out_entry")
    b.attach_kprobe(event="ip_finish_output", fn_name="ip_finish_output_entry")
    b.attach_kprobe(event="ip_forward_finish", fn_name="ip_forward_finish_entry")

    # Get default network namespace inode number
    default_net_ns_inode_number = os.stat('/proc/1/ns/net').st_ino

    print("Tracing ingress and egress messages from containers ... Hit Ctrl-C to end")
    b["ingress"].open_perf_buffer(log_ingress_event)
    b["egress"].open_perf_buffer(log_egress_event)
    b["egress_after_nat"].open_perf_buffer(log_egress_after_nat_event)
    b["egress_forward"].open_perf_buffer(log_egress_forward_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("Exiting.")
            exit()

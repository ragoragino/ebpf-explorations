from bcc import BPF
from socket import inet_ntop, AF_INET
from struct import pack
import os
import ctypes as ct


TASK_COMM_LEN = 16 # linux/sched.h
IFNAMSIZ = 16 # linux/if.h
ETH_ALEN = 6 # uapi/linux/if_ether.h


class CommonEvent(ct.Structure):
    _fields_ = [("timestamp", ct.c_uint64),
                ("proc_inode_numer", ct.c_uint32),
                ("pid", ct.c_uint32),
                ("tgid", ct.c_uint32),
                ("comm", ct.c_char * TASK_COMM_LEN)]

class L2Event(ct.Structure):
    _fields_ = [("dev_name", ct.c_char * IFNAMSIZ),
                ("mac_dest", ct.c_ubyte * ETH_ALEN),
                ("mac_src", ct.c_ubyte * ETH_ALEN)]

class L3Event(ct.Structure):
    _fields_ = [("saddr", ct.c_uint32),
                ("daddr", ct.c_uint32),
                ("protocol", ct.c_uint8)]

class Data(ct.Structure):
    _fields_ = [("common", CommonEvent),
                ("l2", L2Event),
                ("l3", L3Event)]


# Namespace where some kernel threads are running, like swapper
kernel_namespace=3224154216

def convert_bytes_to_hex(table):
    return ':'.join('%02X' % b for b in table)


def log_ingress_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    if filter_event(event.common, event.l3, default_net_ns_inode_number):
        return

    common_event = serialize_common_event(event.common)
    l2_event = serialize_l2_event(event.l2)
    l3_event = serialize_l3_event(event.l3)

    print(f'INGRESS; {common_event}; ; {l3_event}; {l2_event}')


def log_ingress_after_nat_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    
    if filter_event(event.common, event.l3, default_net_ns_inode_number):
        return

    common_event = serialize_common_event(event.common)
    l2_event = serialize_l2_event(event.l2)
    l3_event = serialize_l3_event(event.l3)

    print(f'INGRESS_AFTER_NAT; {common_event}; {l3_event}; {l2_event}')


def log_egress_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    
    if filter_event(event.common, event.l3,default_net_ns_inode_number):
        return

    common_event = serialize_common_event(event.common)
    l2_event = serialize_l2_event(event.l2)
    l3_event = serialize_l3_event(event.l3)

    print(f'EGRESS; {common_event}; {l3_event}; {l2_event}')


def log_egress_after_nat_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    
    if filter_event(event.common, event.l3,default_net_ns_inode_number):
        return

    common_event = serialize_common_event(event.common)
    l2_event = serialize_l2_event(event.l2)
    l3_event = serialize_l3_event(event.l3)

    print(f'EGRESS_AFTER_NAT; {common_event}; {l3_event}; {l2_event}')


def log_forward_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    
    if filter_event(event.common, event.l3, default_net_ns_inode_number):
        return

    common_event = serialize_common_event(event.common)
    l2_event = serialize_l2_event(event.l2)
    l3_event = serialize_l3_event(event.l3)

    print(f'FORWARD; {common_event}; {l3_event}; {l2_event}')


def filter_event(common_data, l3_data, default_net_ns_inode_number):
    # Filter out default namespace traffic and also the internal kernel namespace traffic (swapper and so on)
    if common_data.proc_inode_numer in (kernel_namespace,):
        return True

    # Filter non-ICMP traffic
    if l3_data.protocol != 1:
        return True

    return False


def serialize_common_event(event):
    return f'Timestamp: {event.timestamp}; PID: {event.pid}; TID: {event.tgid}; Inode: {event.proc_inode_numer}; Name: {event.comm}'


def serialize_l2_event(event):
    mac_src = convert_bytes_to_hex(event.mac_src)
    mac_dest = convert_bytes_to_hex(event.mac_dest)

    return f'DeviceName: {event.dev_name}; SrcMac: {mac_src}; DestMac: {mac_dest}'


def serialize_l3_event(event):
    src_address = inet_ntop(AF_INET, pack('I', event.saddr))
    dest_address = inet_ntop(AF_INET, pack('I', event.daddr)) 

    return f'Source: {src_address}; Destination: {dest_address}; Protocol: {event.protocol}'


if __name__ == '__main__':
    print("Running net_ns_tracer.c.")
    b = BPF(src_file="net_ns_tracer.c")

    # Ingress
    b.attach_kprobe(event="ip_rcv", fn_name="ip_rcv_entry")
    b.attach_kprobe(event="ip_rcv_core.isra.20", fn_name="ip_rcv_core_entry")
    b.attach_kretprobe(event="ip_rcv_core.isra.20", fn_name="ip_rcv_core_exit")

    # Egress
    b.attach_kprobe(event="ip_rcv_finish", fn_name="ip_rcv_finish_entry")
    b.attach_kretprobe(event="ip_rcv_finish_core.isra.18", fn_name="ip_rcv_finish_exit")

    # Egress
    b.attach_kprobe(event="ip_output", fn_name="ip_output_entry")

    # Egress after NAT
    b.attach_kprobe(event="ip_finish_output2", fn_name="ip_finish_output2_entry")
    b.attach_kprobe(event="dev_queue_xmit", fn_name="dev_queue_xmit_entry")

    # Forward
    b.attach_kprobe(event="ip_forward_finish", fn_name="ip_forward_finish_entry")

    # Get default network namespace inode number
    default_net_ns_inode_number = os.stat('/proc/1/ns/net').st_ino

    print("Tracing ingress and egress messages from containers ... Hit Ctrl-C to end")
    b["ingress"].open_perf_buffer(log_ingress_event)
    b["ingress_after_nat"].open_perf_buffer(log_ingress_after_nat_event)
    b["egress"].open_perf_buffer(log_egress_event)
    b["egress_after_nat"].open_perf_buffer(log_egress_after_nat_event)
    b["egress_forward"].open_perf_buffer(log_forward_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("Exiting.")
            exit()

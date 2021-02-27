from bcc import BPF
from socket import inet_ntop, ntohs, AF_INET
from struct import pack
import argparse

def log_event(cpu, data, size):
    event = b["events"].event(data)
    src_address = inet_ntop(AF_INET, pack('I', event.saddr))
    dest_address = inet_ntop(AF_INET, pack('I', event.daddr)) 

    print(f'Source: {src_address}; Destination: {dest_address}; Protocol: {event.protocol}')

    if args.program_type == "ip_rcv":
        print(f'Source: {src_address}; Destination: {dest_address}; Protocol: {event.protocol}; Dropped: {event.nf_drooped}.')
    else:
        print(f'Source: {src_address}; Destination: {dest_address}; Protocol: {event.protocol}.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Optional app description')

    parser.add_argument('program_type', type=str, help='ip_rcv or ip_rcv_core')
    args = parser.parse_args()

    if args.program_type == "ip_rcv":
        print("Running ip_rcv_tracer.c.")
        b = BPF(src_file="ip_rcv_tracer.c")
        b.attach_kprobe(event="ip_rcv", fn_name="ip_rcv_enter")
        b.attach_kretprobe(event="ip_rcv", fn_name="ip_rcv_exit")
    else:
        print("Running ip_rcv_core_tracer.c.")
        b = BPF(src_file="ip_rcv_core_tracer.c")
        b.attach_kretprobe(event="ip_rcv_core.isra.20", fn_name="ip_rcv_core_exit")

    print("Tracing ICMP messages ... Hit Ctrl-C to end")
    b["events"].open_perf_buffer(log_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("Exiting.")
            exit()

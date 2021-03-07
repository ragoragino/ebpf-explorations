from bcc import BPF
from socket import inet_ntop, AF_INET
from struct import pack

def log_event(cpu, data, size):
    event = b["events"].event(data)
    src_address = inet_ntop(AF_INET, pack('I', event.saddr))
    dest_address = inet_ntop(AF_INET, pack('I', event.daddr)) 

    print(f'Source: {src_address}; Destination: {dest_address}; Protocol: {event.protocol}.')


if __name__ == '__main__':
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

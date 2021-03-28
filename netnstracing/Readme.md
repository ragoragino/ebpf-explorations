A simple eBPF program tracing network from/to containers with eBPF.


EGRESS; Timestamp: 129572544362742; Source: 172.17.0.2; Destination: 172.217.23.238; Protocol: 1; PID: 23901; TID: 23901; Inode: 4026532357; Name: b'ping' \
EGRESS_AFTER_NAT; Timestamp: 129572544407654; Source: 172.17.0.2; Destination: 172.217.23.238; Protocol: 1; PID: 23901; TID: 23901; Inode: 4026532357; Name: b'ping' \
INGRESS; Timestamp: 129572544508889; Source: 172.17.0.2; Destination: 172.217.23.238; Protocol: 1; PID: 23901; TID: 23901; Inode: 2539808872; Name: b'ping' \
FORWARD; Timestamp: 129572544557976; Source: 172.17.0.2; Destination: 172.217.23.238; Protocol: 1; PID: 23901; TID: 23901; Inode: 4026531992; Name: b'ping' \
EGRESS_AFTER_NAT; Timestamp: 129572544582810; Source: 192.168.0.10; Destination: 172.217.23.238; Protocol: 1; PID: 23901; TID: 23901; Inode: 4026531992; Name: b'ping' \

INGRESS; Timestamp: 132381848510823; Source: 172.217.23.238; Destination: 192.168.0.10; Protocol: 1; PID: 2398; TID: 2398; Inode: 2539808872; Name: b'Xorg'; DeviceName: b'wlo1' \
FORWARD; Timestamp: 132381848592527; Source: 172.217.23.238; Destination: 172.17.0.2; Protocol: 1; PID: 2398; TID: 2398; Inode: 4026531992; Name: b'Xorg'; DeviceName: b'docker0' \
EGRESS_AFTER_NAT; Timestamp: 132381848610303; Source: 172.217.23.238; Destination: 172.17.0.2; Protocol: 1; PID: 2398; TID: 2398; Inode: 4026531992; Name: b'Xorg'; DeviceName: b'docker0' \
INGRESS; Timestamp: 132381848680443; Source: 172.217.23.238; Destination: 172.17.0.2; Protocol: 1; PID: 2398; TID: 2398; Inode: 0; Name: b'Xorg'; DeviceName: b'eth0' \

https://wiki.aalto.fi/download/attachments/70789059/linux-kernel-ip.pdf
https://helda.helsinki.fi/bitstream/handle/10138/320475/Viding_Jasu_DemystifyingContainerNetworking_2020.pdf?sequence=2&isAllowed=y

# Update 28.3.2021:

# TODO: Get MAC addresses
# TODO: Get ICMP ID
# TODO: Get ICMP Type
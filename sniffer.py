import socket
import struct
import time
import collections

# PROTOCOLS dictionary
PROTOCOLS = {4: 'ip', 41:'ip', 6:'tcp', 17: 'udp',
            1: 'icmp'}

# count of PROTOCOLS
result = collections.OrderedDict()
protos = ['ip', 'tcp', 'udp', 'DNS', 'icmp', 'http', 'https', 'quic']
for k in protos:
    result[k] = 0

# create a raw socket connection
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

# set the time limit
time_till = time.time() + 30

while time.time() < time_till:
    packet, address = raw_socket.recvfrom(65535)

    # ethernet frame
    ethernet_header = packet[:14]
    ethernet_unpacked = struct.unpack('!6B 6B H', ethernet_header)
    eth_protocol = socket.htons(ethernet_unpacked[2])
    if eth_protocol in PROTOCOLS:
        result[PROTOCOLS[eth_protocol]] += 1
    
    # ip frame
    ip_header = packet[14:34]
    ip_unpacked = struct.unpack("! 9x B 2x 4s 4s", ip_header)
    ip_proto = ip_unpacked[0]
    
    if ip_proto in PROTOCOLS and PROTOCOLS[ip_proto] == 'tcp':
        # increment for tcp, ip
        result['tcp'] += 1
        result['ip'] += 1
        # check for http
        tcp_header = packet[34:48]
        port_num = struct.unpack("! H H L L H", tcp_header)
        src_port = port_num[0]
        dest_port = port_num[1]
        if src_port == 443:
            result['https'] += 1
        if dest_port == 443:
            result['https'] += 1
        if src_port == 80:
            result['http'] += 1
        if dest_port == 80:
            result['http'] += 1
        if src_port == 53:
            result['DNS'] += 1
        if dest_port == 53:
            result['DNS'] += 1
    elif ip_proto in PROTOCOLS and PROTOCOLS[ip_proto] == 'udp':
        # increment for udp and ip
        result['udp'] += 1
        result['ip'] += 1
        # if port number is 53 in IP Header then its DNS
        udp_header = packet[34:42]
        port_num = struct.unpack("! H H 4s", udp_header)
        src_port = port_num[0]
        dest_port = port_num[1]
        if src_port == 53:
            result['DNS'] += 1
        if dest_port == 53:
            result['DNS'] += 1
        if src_port == 443:
            result['quic'] += 1
        if dest_port == 443:
            result['quic'] += 1
        if src_port == 80:
            result['quic'] += 1
        if dest_port == 80:
            result['quic'] += 1
    elif ip_proto in PROTOCOLS and PROTOCOLS[ip_proto] == 'icmp':
        result['icmp'] += 1

with open('sniffer_rghorse.csv', 'w') as f: 
    f.write('protocol,count\n')
    for k,v in result.items():
        f.write(k+','+str(v)+'\n')
    f.close()   
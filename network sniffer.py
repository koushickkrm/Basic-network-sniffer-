import socket
import struct
import textwrap

INDENT_1 = "  - "
INDENT_2 = "    - "
INDENT_3 = "      - "
INDENT_4 = "        - "

DATA_INDENT_1 = "  "
DATA_INDENT_2 = "    "
DATA_INDENT_3 = "      "
DATA_INDENT_4 = "        "

def main():
    # Create a raw socket to capture all network traffic (Unix-like systems)
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except AttributeError:
        print("Raw sockets are not supported on this system.")
        return

    # Continuously listen for incoming packets
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = parse_ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print(INDENT_1 + f"Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

        # Check for IPv4 packets
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = parse_ipv4_packet(data)
            print(INDENT_1 + "IPv4 Packet:")
            print(INDENT_2 + f"Version: {version}, Header Length: {header_length}, TTL: {ttl}")
            print(INDENT_2 + f"Protocol: {proto}, Source: {src}, Target: {target}")

            # Process the packet based on its protocol
            if proto == 1:
                process_icmp_packet(data)
            elif proto == 6:
                process_tcp_segment(data)
            elif proto == 17:
                process_udp_segment(data)
            else:
                print(INDENT_1 + "Data:")
                print(format_data(DATA_INDENT_2, data))
        else:
            print("Data:")
            print(format_data(DATA_INDENT_1, data))

def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac_address(dest_mac), format_mac_address(src_mac), socket.htons(proto), data[14:]

def format_mac_address(bytes_addr):
    return ':'.join(f'{b:02x}' for b in bytes_addr).upper()

def parse_ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ipv4_address(src), format_ipv4_address(target), data[header_length:]

def format_ipv4_address(addr):
    return '.'.join(map(str, addr))

def process_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    print(INDENT_1 + "ICMP Packet:")
    print(INDENT_2 + f"Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
    print(INDENT_2 + "Data:")
    print(format_data(DATA_INDENT_3, data[4:]))

def process_tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x1FF
    flag_urg = (flags & 32) >> 5
    flag_ack = (flags & 16) >> 4
    flag_psh = (flags & 8) >> 3
    flag_rst = (flags & 4) >> 2
    flag_syn = (flags & 2) >> 1
    flag_fin = flags & 1

    print(INDENT_1 + "TCP Segment:")
    print(INDENT_2 + f"Source Port: {src_port}, Destination Port: {dest_port}")
    print(INDENT_2 + f"Sequence: {sequence}, Acknowledgement: {acknowledgement}")
    print(INDENT_2 + "Flags:")
    print(INDENT_3 + f"URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}")
    print(INDENT_2 + "Data:")
    print(format_data(DATA_INDENT_3, data[offset:]))

def process_udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    print(INDENT_1 + "UDP Segment:")
    print(INDENT_2 + f"Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}")
    print(INDENT_2 + "Data:")
    print(format_data(DATA_INDENT_3, data[8:]))

def format_data(prefix, string, size=80):
    if isinstance(string, bytes):
        string = ''.join(f'{byte:02x}' for byte in string)
    size = size * 3
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
    main()

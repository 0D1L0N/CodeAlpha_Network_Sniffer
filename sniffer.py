import socket
import struct
import textwrap

# Packet Sniffer Class
class PacketSniffer:
    def __init__(self, interface=None):
        self.sock = self.create_socket(interface)

    def create_socket(self, interface=None):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        if interface:
            sock.bind((interface, 0))
        return sock

    def listen(self):
        while True:
            raw_data, addr = self.sock.recvfrom(65536)
            yield raw_data

    def parse_packet(self, raw_data):
        eth_header = raw_data[:14]
        eth = struct.unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])

        if eth_protocol == 8:  # IP Protocol
            ip_header = raw_data[14:34]
            ip = struct.unpack('!BBHHHBBH4s4s', ip_header)
            ttl = ip[5]
            protocol = ip[6]
            src_ip = socket.inet_ntoa(ip[8])
            dest_ip = socket.inet_ntoa(ip[9])
            packet_length = len(raw_data)

            # Extract TCP/UDP ports if the protocol is TCP (6) or UDP (17)
            src_port = dest_port = None
            if protocol == 6:  # TCP
                tcp_header = raw_data[34:54]
                tcp = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port = tcp[0]
                dest_port = tcp[1]
            elif protocol == 17:  # UDP
                udp_header = raw_data[34:42]
                udp = struct.unpack('!HHHH', udp_header)
                src_port = udp[0]
                dest_port = udp[1]

            return {
                'eth_protocol': eth_protocol,
                'ttl': ttl,
                'protocol': protocol,
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'length': packet_length,
                'src_port': src_port,
                'dest_port': dest_port,
                'protocol_name': self.get_protocol_name(protocol),
            }

        return None

    def get_protocol_name(self, protocol):
        # Convert protocol number to human-readable name
        if protocol == 1:
            return 'ICMP'
        elif protocol == 6:
            return 'TCP'
        elif protocol == 17:
            return 'UDP'
        else:
            return 'Unknown'

    def display_packet(self, packet_info):
        if packet_info:
            print("------------------------------------------------------------")
            print(f"Ethernet Protocol: {packet_info['eth_protocol']}")
            print(f"TTL: {packet_info['ttl']}")
            print(f"Protocol: {packet_info['protocol_name']}")
            print(f"Source IP: {packet_info['src_ip']} -> Destination IP: {packet_info['dest_ip']}")
            print(f"Source Port: {packet_info['src_port'] if packet_info['src_port'] else 'N/A'}")
            print(f"Destination Port: {packet_info['dest_port'] if packet_info['dest_port'] else 'N/A'}")
            print(f"Packet Length: {packet_info['length']} bytes")
            print("------------------------------------------------------------")

# Main Code
if __name__ == "__main__":
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Network packet sniffer")
    parser.add_argument("-i", "--interface", type=str, help="Interface for capturing packets")
    _args = parser.parse_args()

    if os.getuid() != 0:
        raise SystemExit("Error: This application requires administrator privileges.")

    sniffer = PacketSniffer(_args.interface)

    # Announcement message
    print("[*] Starting packet sniffer on interface: {}".format(_args.interface))
    print("[*] Listening for packets... Press Ctrl+C to stop.")

    try:
        for raw_packet in sniffer.listen():
            packet_info = sniffer.parse_packet(raw_packet)
            sniffer.display_packet(packet_info)
    except KeyboardInterrupt:
        raise SystemExit("[!] Stopping packet capture...")

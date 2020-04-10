# Python packet sniffer for Linux

import socket
import numpy as np
import sys

from link import parse_frame
from network import parse_ip_datagram, parse_arp_datagram
from transport import parse_udp_segment, parse_tcp_segment
from application import parse_dns_msg, parse_http_msg

# Run packet sniffer
def sniffer(max_pkts = np.inf):
    """
    Parameters:
    max_pkts: int, default: inf
        The maximum number of packets to be collected by the sniffer.
        Default is to continue collecting packets forever.
    """

    # Create raw socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    ctr = 0

    while ctr < max_pkts:
        print("Packet: ", ctr)

        # Receive ethernet frame from socket
        frame, addr = sock.recvfrom(65536)

        # Parse ethernet frame
        dst_mac, src_mac, eth_type, eth_payload = parse_frame(frame)

        print("  Ethernet, Type:", eth_type, "  Src MAC:", src_mac, " Dst MAC:", dst_mac)

        # Parse IP datagram
        if eth_type == 'IPv4':
            src_ip, dst_ip, ip_prot, ip_payload = parse_ip_datagram(eth_payload)

            print("  Internet Protocol v4, Protocol:", ip_prot,
                    " Src IP:", src_ip, " Dst IP:", dst_ip)

            if ip_prot == 'UDP':
                src_port, dst_port, udp_payload, app_type, direction =\
                        parse_udp_segment(ip_payload)

                print("  User Datagram Protocol (", direction, ") Type:", app_type,  
                        " Src Port:", src_port, " Dst Port:", dst_port)

                if app_type == 'DNS':
                    query_id, qr_code, questions, answers, auth_rrs, add_rrs,\
                        q_list, a_list = parse_dns_msg(udp_payload)

                    print("  Domain Name System (", qr_code, ") Query ID:", query_id,
                            "\n\tQuestions:", questions, " Answer RRs:", answers,
                            " Authority RRs:", auth_rrs, "Additional RRs:", add_rrs)        

                    if len(q_list) > 0:
                        print("\tQueries:")
                        for q in q_list:
                            print("\t  ", q[0], " Type:", q[1])

                    if len(a_list) > 0:
                        print("\tAnswers:")
                        for a in a_list:
                            print("\t  ", a[0], " Type:", a[1], " Addr:", a[3])

            elif ip_prot == 'TCP':
                src_port, dst_port, tcp_payload, app_type, direction,\
                    flags, seq_num, ack_num = parse_tcp_segment(ip_payload)

                print("  Transmission Control Protocol (", direction, ") Type:",
                        app_type,
                        "\n\tSeq num:", seq_num, " Ack num:", ack_num,
                        "\n\tSrc Port:", src_port, " Dst Port:", dst_port,
                        " Flags:", flags)

                http_output = parse_http_msg(tcp_payload)

                if app_type == "HTTP":
                    http_output = parse_http_msg(tcp_payload)
                    if len(http_output) > 0:
                        print("  HyperText Transfer Protocol:")
                        for row in http_output:
                            print("\t", row)

        elif eth_type == 'ARP':
            arp_src_mac, arp_dst_mac, src_ip, dst_ip, opcode =\
                parse_arp_datagram(eth_payload)

            print("  Address Resolution Protocol (", opcode, ")",
                    "\n    Sender MAC:", arp_src_mac, "Sender IP:", src_ip,
                    "\n    Target MAC:", arp_dst_mac, "Target IP:", dst_ip)

        ctr += 1


if __name__ == "__main__":
    if len(sys.argv) > 1:
        max_pkt = int(sys.argv[1])
        sniffer(max_pkt)

    else:
        sniffer()

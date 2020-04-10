""" Functions for parsing network layer datagrams."""

import struct
from link import format_mac

# Format IPv4 address
def format_ip(ip_addr):
    formatted = '.'.join(str(byte) for byte in ip_addr)
    return formatted

# Translate IP protocol code
def translate_ip_protocol(protocol):
    if protocol == 6:
        trans_type = 'TCP'
    elif protocol == 17:
        trans_type = 'UDP'
    else:
        trans_type = 'OTHER'

    return trans_type

# Parse an IPv4 datagram
def parse_ip_datagram(dgram):
    # Get header length and datagram length
    header_len = '{0:08b}'.format(dgram[0])[-4:]
    dgram_len = struct.unpack('! H', dgram[2:4])[0]

    # Split datagram into header and payload
    if header_len == '0101':
        ip_header = dgram[0:20]
        ip_payload = dgram[20:dgram_len]
    else:
        ip_header = dgram[0:24]
        ip_payload = dgram[24:dgram_len]

    # Convert header bytes to data
    protocol = ip_header[9]
    src_ip = ip_header[12:16]
    dst_ip = ip_header[16:20]

    return (format_ip(src_ip), format_ip(dst_ip), translate_ip_protocol(protocol), ip_payload)

# Translate ARP Opcode
def translate_arp_opcode(opcode):
    if opcode == 1:
        trans_type = 'ARP Request'
    elif opcode == 2:
        trans_type = 'ARP Reply'
    else:
        trans_type = 'OTHER'

    return trans_type

# Parse ARP datagram
def parse_arp_datagram(dgram):
    # Check hardware and protocol lengths are as expected
    if dgram[4] == 6 and dgram[5] == 4:
        # If so, extract data from header
        opcode, arp_src_mac, src_ip, arp_dst_mac, dst_ip =\
            struct.unpack('! H 6s 4s 6s 4s', dgram[6:28])

        return (format_mac(arp_src_mac), format_mac(arp_dst_mac),
                format_ip(src_ip), format_ip(dst_ip), translate_arp_opcode(opcode))

    else:
        # If not, just extract Opcode
        opcode = struct.unpack('! H', dgram[6:8])[0]

        return ('NA', 'NA', 'NA', 'NA', translate_arp_opcode(opcode))

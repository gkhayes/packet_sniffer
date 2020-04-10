""" Functions for parsing link layer frames. """

import struct

# Format MAC address
def format_mac(mac_addr):
    formatted = ':'.join('{:02x}'.format(byte) for byte in mac_addr)
    return formatted

# Translate ethernet protocol code
def translate_eth_type(eth_type):
    if eth_type == 2048:
        trans_type = 'IPv4'
    elif eth_type == 2054:
        trans_type = 'ARP'
    else:
        trans_type = 'OTHER'

    return trans_type

# Parse an ethernet frame
def parse_frame(frame):
    # Split frame into header and payload
    eth_header = frame[0:14]
    eth_payload = frame[14:]

    # Convert header bytes to data
    dst_mac, src_mac, eth_type = struct.unpack('! 6s 6s H', eth_header)

    return (format_mac(dst_mac), format_mac(src_mac), translate_eth_type(eth_type),
            eth_payload)



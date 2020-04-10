""" Functions for parsing transport layer segments."""

import struct

# Translate well known TCP and UDP ports
def translate_port(port):
    if port == 20 or port == 21:
        port_type = 'FTP'
    elif port == 22:
        port_type = 'SSH'
    elif port == 23:
        port_type = 'TELNET'
    elif port == 25:
        port_type = 'SMTP'
    elif port == 53:
        port_type = 'DNS'
    elif port == 80:
        port_type = 'HTTP'
    elif port == 443:
        port_type = 'HTTPS'
    else:
        port_type = 'OTHER'

    return port_type

# Parse UDP segment
def parse_udp_segment(segment):
    # Split datagram into header and payload
    udp_header = segment[0:8]
    udp_payload = segment[8:]

    # Extract port numbers from header
    src_port, dst_port = struct.unpack('! H H', segment[0:4])

    # Determine application type
    src_type = translate_port(src_port)
    dst_type = translate_port(dst_port)

    if src_type != 'OTHER':
        app_type = src_type
        direction = 'Response'
    elif dst_type != 'OTHER':
        app_type = dst_type
        direction = 'Request'
    else:
        app_type = 'OTHER'
        direction = 'NA'

    return (src_port, dst_port, udp_payload, app_type, direction)

# Parse TCP segment
def parse_tcp_segment(segment):
    # Get header length
    header_len = int(4*segment[12]/16)

    # Split segment into header and payload
    tcp_header = segment[0:header_len]
    tcp_payload = segment[header_len:]

    # Extract information from header
    src_port, dst_port, seq_num, ack_num = struct.unpack('! H H I I', segment[0:12])

    # Extract flags
    flags = '{0:08b}'.format(segment[13])

    flags_list = list()

    if int(flags[0]) == 1:
        flags_list.append('CWR')
    if int(flags[1]) == 1:
        flags_list.append('ECE')
    if int(flags[2]) == 1:
        flags_list.append('URG')
    if int(flags[3]) == 1:
        flags_list.append('ACK')
    if int(flags[4]) == 1:
        flags_list.append('PSH')
    if int(flags[5]) == 1:
        flags_list.append('RST')
    if int(flags[6]) == 1:
        flags_list.append('SYN')
    if int(flags[7]) == 1:
        flags_list.append('FIN')

    # Determine application type
    src_type = translate_port(src_port)
    dst_type = translate_port(dst_port)

    if src_type != 'OTHER':
        app_type = src_type
        direction = 'RESPONSE'
    elif dst_type != 'OTHER':
        app_type = dst_type
        direction = 'REQUEST'
    else:
        app_type = 'OTHER'
        direction = 'NA'

    return (src_port, dst_port, tcp_payload, app_type, direction,
            flags_list, seq_num, ack_num)

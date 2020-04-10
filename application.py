""" Functions for parsing application layer messages."""

import struct
import re
from network import format_ip

# Extract URL from DNS question
# Source: https://stackoverflow.com/questions/16977588/reading-dns-packets-in-python
def extract_dns_url(payload, offset = 0):
    output = []

    while True:
        length, = struct.unpack_from('! B', payload, offset)

        if length == 192:
            offset += 2
            return output, offset

        offset += 1

        if length == 0:
            return output, offset

        output.append(struct.unpack_from('!%ds' % length, payload, offset)[0].decode("utf-8"))
        offset += length

# Translate DNS type code
def translate_dns_type(code):
    if code == 1:
        dns_type = 'A'
    elif code == 5:
        dns_type = 'CNAME'
    elif code == 28:
        dns_type = 'AAAA'
    else:
        dns_type = 'OTHER'
    return dns_type

# Decode DNS question
def decode_dns_question(payload, offset = 0):
    # Extract first question URL after offset
    output, new_offset = extract_dns_url(payload, offset)

    # Convert output to url
    url = '.'.join(output)

    # Extract type and class of question from payload
    dns_type, dns_class = struct.unpack('! H H', payload[new_offset: new_offset + 4])

    return url, translate_dns_type(dns_type), dns_class, new_offset + 4

# Decode DNS resource
def decode_dns_resource(payload, last_url, offset = 0):
    # Extract record name
    output, new_offset = extract_dns_url(payload, offset)

    # Convert output to url
    if len(output) == 0:
        url = last_url

    else:
        url = '.'.join(output)

    # Extract type class and record length
    dns_type, dns_class, ttl, rec_len = struct.unpack('! H H I H', payload[new_offset: new_offset+10])

    # Extract record data
    rec_data = payload[new_offset + 10: new_offset + 10 + rec_len]

    new_offset += 10 + rec_len

    return url, translate_dns_type(dns_type), dns_class, rec_data, new_offset

# Find longest sequence of zeros
def longest_seq(block_list):
    # Initialize variables
    max_start = -1
    max_end = -1
    max_len = 0

    seq_start = -1
    seq_end = -1
    seq_len = 0

    # Find longest sequence
    for i in range(len(block_list)):
        block = block_list[i]
        if block == '0':
            if seq_len == 0:
                seq_start = i
                seq_end = i
            else:
                seq_end += 1

            seq_len += 1
        else:
            if seq_len > max_len:
                max_len = seq_len
                max_start = seq_start
                max_end = seq_end

            seq_len = 0
            seq_start = -1
            seq_end = -1

    return max_len, max_start, max_end

# Compress IPv6 address according to shortening rules
def compress_list(block_list):
    max_len, max_start, max_end = longest_seq(block_list)

    if max_len > 1:
        for i in range(max_start, max_end + 1):
            block_list[i] = ''

    return block_list

# Reduce sequence lengthening
# Source: https://rustyonrampage.github.io/text-mining/2017/11/28/spelling-correction-with-python-and-nltk.html
def reduce_lengthening(text):
    pattern = re.compile(r"(.)\1{2,}")
    return pattern.sub(r"\1\1", text)

# Format IPv6 address
def format_ipv6(ipv6_add):
    hex_addr = ipv6_add.hex()

    # Break up address into 4 digit blocks
    blocks = []
    for i in range(0, 32, 4):
        block = hex_addr[i:i+4].lstrip("0")

        if block == '':
            block = '0'

        blocks.append(block)

    # Convert block list to formatted IPv6 address
    address = ':'.join(compress_list(blocks))
    formatted = reduce_lengthening(address)

    return formatted

# Translate QR code
def translate_qr(code):
    if code == 0:
        trans = "Query"
    else:
        trans = "Response"
    return trans

# Parse DNS message
def parse_dns_msg(msg):
    # Split message into header and payload
    dns_header = msg[0:12]
    dns_payload = msg[12:]

    # Extract info from DNS header
    query_id, flags, questions, answers, auth_rrs, add_rrs =\
            struct.unpack('! H H H H H H', dns_header)

    flags = '{0:016b}'.format(flags)
    qr_code = int(flags[0])

    offset = 0
    q_list = list()
    a_list = list()
    auth_list = list()
    add_list = list()

    # Extract questions
    if questions > 0:
        q_cnt = 0
        last_url = 'NULL'

        while q_cnt < questions:
            url, dns_type, dns_class, offset = decode_dns_question(dns_payload, offset)
            q_list.append((url, dns_type, dns_class))
            last_url = url
            q_cnt += 1

    # Extract answers
    if answers > 0 and q_list[-1][1] != 'OTHER':
        a_cnt = 0

        while a_cnt < answers:
            url, dns_type, dns_class, rec_data, offset = decode_dns_resource(dns_payload, last_url, offset)

            # Translate CNAME record data to URL
            if dns_type == 'CNAME':
                cname_output, _ = extract_dns_url(rec_data)
                cname_url = '.'.join(cname_output)
                a_list.append((url, dns_type, dns_class, cname_url))
                last_url = cname_url

            # Translate A record data to IPv4 address
            elif dns_type == 'A':
                a_ip = format_ip(rec_data)
                a_list.append((url, dns_type, dns_class, a_ip))

            # Translate AAAA record data to IPv6 address
            elif dns_type == 'AAAA':
                aaaa_ip = format_ipv6(rec_data)
                a_list.append((url, dns_type, dns_class, aaaa_ip))

            a_cnt += 1

    return (query_id, translate_qr(qr_code), questions, answers, auth_rrs,
            add_rrs, q_list, a_list)

# Parse HTTP message and return header information
def parse_http_msg(msg):
    # Decode bytes
    content = msg.decode('utf-8', 'ignore')

    # Split decoded content to remove message
    output_list = content.split('\r\n')

    # Rejoin dropping last two items
    if len(output_list) > 2:
        output = output_list[:-2]
    else:
        output = []

    return output

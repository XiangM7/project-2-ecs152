import random
import socket
import struct
import sys
import time

# the servers from the assignment list
PUBLIC_DNS_SERVERS = [
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
]

# dns mapping for printing
TYPE_TO_NAME = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}

# use struct to build the dns query packet
def build_query(domain: str, qtype: int = 1):
    # 
    head_id = random.randint(0, 0xFFFF)
    # 0 : standard query, 0: opcode, 0: AA, 0: not truncated, 0: recursion, 0: (for responses)available, 0: reserved, 0: rcode
    flags = 0x0000
    header = struct.pack("!HHHHHH", head_id, flags, 1, 0, 0, 0)

    # build q_name from domain and pack into bytrs
    q_name = b""
    for label in domain.strip(".").split("."):
        q_name += struct.pack("!B", len(label)) + label.encode("ascii")
    q_name += b"\x00"

    # return the query packet
    question = q_name + struct.pack("!HH", qtype, 1)
    return header + question

# dns decoding for response
def read_name(data: bytes, offset: int):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        # if there is a zero length, we are done
        if length == 0:
            offset += 1
            break

        # if we find a pointee we jump to the location and read from there
        if (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = ptr
            jumped = True
            continue

        offset += 1
        labels.append(data[offset: offset + length].decode("ascii", errors="replace"))
        offset += length

    # onlt if jumped from a pointer, otherwise use the regular offset
    if jumped:
        return ".".join(labels), original_offset
    return ".".join(labels), offset

# parse the r_data based on the type
def parse_r_data(data: bytes, rtype: int, r_data_offset: int, rd_length: int):
    r_data = data[r_data_offset:r_data_offset + rd_length]

    # record type A and AAAA are just the ip address
    if rtype == 1 and rd_length == 4:
        return socket.inet_ntoa(r_data)
    if rtype == 28 and rd_length == 16:
        return socket.inet_ntop(socket.AF_INET6, r_data)

    # NS and CNAME are names that need to be read with read_name
    if rtype in (2, 5):
        name, _ = read_name(data, r_data_offset)
        return name

    # return hex otherwise
    return r_data.hex()


def parse_dns_response(packet: bytes):
    # take off the header
    head_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    offset = 12

    # add offset for the question section
    for i in range(qdcount):
        _, offset = read_name(packet, offset)
        offset += 4

    # loop through the sections and records and parse them
    records = []
    for section, count in (("answer", ancount), ("authority", nscount), ("additional", arcount)):
        for i in range(count):

            # read the name and account for offset if there is jumping
            name, offset = read_name(packet, offset)
            rtype, rclass, ttl, rd_length = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            r_data_offset = offset

            # parse the r data based and get the record type and value
            value = parse_r_data(packet, rtype, r_data_offset, rd_length)
            offset += rd_length

            # add the record to lsit
            records.append({
                "section": section,
                "name": name,
                "type": rtype,
                "type_name": TYPE_TO_NAME.get(rtype, f"TYPE{rtype}"),
                "class": rclass,
                "ttl": ttl,
                "value": value,
            })
    # return header information and records
    return {
        "head_id": head_id,
        "flags": flags,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "records": records,
    }

# singular query to a dns server and returns the rtt time
def query_dns_server(server_ip: str, domain: str, qtype: int = 1, timeout: float = 10.0):
    query = build_query(domain, qtype=qtype)

    # same socket method
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        sock.sendto(query, (server_ip, 53))
        data, _ = sock.recvfrom(4096)
        rtt_ms = (time.perf_counter() - start) * 1000.0
        return parse_dns_response(data), rtt_ms
    except socket.timeout:
        return None, None
    finally:
        sock.close()

# print query
def print_query_block(server_ip: str, domain: str, records, rtt_ms: float):
    print("--------------------------------------------")
    print(f"Querying {server_ip} for {domain}")
    print("--------------------------------------------")
    for rr in records:
        print(f"{rr['type_name']} : {rr['value']}")
    print(f"RTT: {rtt_ms:.2f} ms")

# the actual iterative resolution logic
def resolve_iterative(domain: str, qtype: int = 1, max_hops: int = 20):
    nameservers = PUBLIC_DNS_SERVERS[:]
    tried = set()

    for i in range(max_hops):
        response = None
        used_server = None
        rtt_ms = None

        # iterate through the nameservers
        for ns in nameservers:
            if ns in tried:
                continue
            # if it hasn't been tried hit it and add it to the tried set
            parsed, hop_rtt = query_dns_server(ns, domain, qtype=qtype, timeout=10.0)
            tried.add(ns)
            # get response and rtt if we got a response
            if parsed is not None:
                response = parsed
                used_server = ns
                rtt_ms = hop_rtt
                break

        if response is None:
            return None

        # print the query block
        records = response["records"]
        print_query_block(used_server, domain, records, rtt_ms)

        # check if we actually for the answer we want and not just another referral
        answer_a = [
            rr for rr in records
            if rr["section"] == "answer" and rr["type"] == 1 and rr["name"].strip(".").lower() == domain.strip(".").lower()
        ]
        if answer_a:
            return answer_a[0]["value"]

        # handling cname aliases and resolve
        cname = [rr for rr in records if rr["section"] == "answer" and rr["type"] == 5]
        if cname:
            domain = cname[0]["value"]
            nameservers = PUBLIC_DNS_SERVERS[:]
            # clear the tried set cause we are trying new servers
            tried = set()
            continue

        # ip of next nameservers in additional section,and try them as well
        glue_ips = [rr["value"] for rr in records if rr["section"] == "additional" and rr["type"] == 1]
        if glue_ips:
            # clear the tried set again
            nameservers = glue_ips
            tried = set()
            continue

        # otherwise we just resolve them ourselves and try them but this is slow
        ns_names = [rr["value"] for rr in records if rr["section"] == "authority" and rr["type"] == 2]
        if ns_names:
            ns_ip = None
            for ns_name in ns_names:
                ns_ip = resolve_iterative(ns_name, qtype=1, max_hops=10)
                if ns_ip:
                    break
            if ns_ip:
                # again clear the tried set cause we are trying new servers
                nameservers = [ns_ip]
                tried = set()
                continue

        return None
    return None

# make the http request to the ip and get the rtt
def make_http_request(ip: str, domain: str):
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")

    # rtt logic, similar to last time
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    try:
        start = time.perf_counter()
        sock.connect((ip, 80))
        sock.sendall(request)
        response = sock.recv(4096)
        rtt_ms = (time.perf_counter() - start) * 1000.0

        first_line = response.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
        parts = first_line.split()
        status_code = parts[1] if len(parts) >= 2 else "UNKNOWN"
        return status_code, rtt_ms
    finally:
        sock.close()


def main():
    # default domain if no commandline argument
    domain = "wikipedia.org"
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip()

    # the first call for iterative resolution
    final_ip = resolve_iterative(domain, qtype=1)
    if not final_ip:
        print("Resolution failed")
        return

    print("--------------------------------------------")
    print(f"Making HTTP request to {final_ip}")
    print("--------------------------------------------")
    status_code, http_rtt = make_http_request(final_ip, domain)
    print(status_code)
    print(f"RTT: {http_rtt:.2f} ms")


if __name__ == "__main__":
    main()

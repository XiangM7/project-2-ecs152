import random
import socket
import struct
import sys
import time


ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "170.247.170.2",   # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
    "199.7.91.13",     # d.root-servers.net
    "192.203.230.10",  # e.root-servers.net
    "192.5.5.241",     # f.root-servers.net
    "192.112.36.4",    # g.root-servers.net
    "198.97.190.53",   # h.root-servers.net
    "192.36.148.17",   # i.root-servers.net
    "192.58.128.30",   # j.root-servers.net
    "193.0.14.129",    # k.root-servers.net
    "199.7.83.42",     # l.root-servers.net
    "202.12.27.33",    # m.root-servers.net
]

TYPE_TO_NAME = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}


def build_dns_query(domain: str, qtype: int = 1) -> bytes:
    txid = random.randint(0, 0xFFFF)
    flags = 0x0000
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)

    qname = b""
    for label in domain.strip(".").split("."):
        qname += struct.pack("!B", len(label)) + label.encode("ascii")
    qname += b"\x00"

    question = qname + struct.pack("!HH", qtype, 1)
    return header + question


def read_name(data: bytes, offset: int):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break

        # DNS compression pointer
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

    if jumped:
        return ".".join(labels), original_offset
    return ".".join(labels), offset


def parse_rdata(data: bytes, rtype: int, rdata_offset: int, rdlength: int) -> str:
    rdata = data[rdata_offset:rdata_offset + rdlength]
    if rtype == 1 and rdlength == 4:  # A
        return socket.inet_ntoa(rdata)
    if rtype == 28 and rdlength == 16:  # AAAA
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (2, 5):  # NS, CNAME
        name, _ = read_name(data, rdata_offset)
        return name
    return rdata.hex()


def parse_dns_response(packet: bytes):
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    offset = 12

    for _ in range(qdcount):
        _, offset = read_name(packet, offset)
        offset += 4

    records = []
    for section, count in (("answer", ancount), ("authority", nscount), ("additional", arcount)):
        for _ in range(count):
            name, offset = read_name(packet, offset)
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            rdata_offset = offset
            value = parse_rdata(packet, rtype, rdata_offset, rdlength)
            offset += rdlength
            records.append({
                "section": section,
                "name": name,
                "type": rtype,
                "type_name": TYPE_TO_NAME.get(rtype, f"TYPE{rtype}"),
                "class": rclass,
                "ttl": ttl,
                "value": value,
            })

    return {
        "txid": txid,
        "flags": flags,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "records": records,
    }


def query_dns_server(server_ip: str, domain: str, qtype: int = 1, timeout: float = 10.0):
    query = build_dns_query(domain, qtype=qtype)
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


def print_query_block(server_ip: str, domain: str, records, rtt_ms: float):
    print("----------------------------------------")
    print(f"Querying {server_ip} for {domain}")
    print("----------------------------------------")
    for rr in records:
        print(f"{rr['type_name']} : {rr['value']}")
    print(f"RTT: {rtt_ms:.2f} ms")


def resolve_iterative(domain: str, qtype: int = 1, max_hops: int = 20):
    nameservers = ROOT_SERVERS[:]
    tried = set()

    for _ in range(max_hops):
        response = None
        used_server = None
        rtt_ms = None

        for ns in nameservers:
            if ns in tried:
                continue
            parsed, hop_rtt = query_dns_server(ns, domain, qtype=qtype, timeout=10.0)
            tried.add(ns)
            if parsed is not None:
                response = parsed
                used_server = ns
                rtt_ms = hop_rtt
                break

        if response is None:
            return None

        records = response["records"]
        print_query_block(used_server, domain, records, rtt_ms)

        answer_a = [
            rr for rr in records
            if rr["section"] == "answer" and rr["type"] == 1 and rr["name"].strip(".").lower() == domain.strip(".").lower()
        ]
        if answer_a:
            return answer_a[0]["value"]

        cname = [rr for rr in records if rr["section"] == "answer" and rr["type"] == 5]
        if cname:
            domain = cname[0]["value"]
            nameservers = ROOT_SERVERS[:]
            tried = set()
            continue

        glue_ips = [rr["value"] for rr in records if rr["section"] == "additional" and rr["type"] == 1]
        if glue_ips:
            nameservers = glue_ips
            tried = set()
            continue

        ns_names = [rr["value"] for rr in records if rr["section"] == "authority" and rr["type"] == 2]
        if ns_names:
            ns_ip = None
            for ns_name in ns_names:
                ns_ip = resolve_iterative(ns_name, qtype=1, max_hops=10)
                if ns_ip:
                    break
            if ns_ip:
                nameservers = [ns_ip]
                tried = set()
                continue

        return None

    return None


def make_http_request(ip: str, domain: str):
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")

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
    domain = "wikipedia.org"
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip()
    if not domain:
        domain = "wikipedia.org"

    final_ip = resolve_iterative(domain, qtype=1)
    if not final_ip:
        print("Resolution failed")
        return

    print("----------------------------------------")
    print(f"Making HTTP request to {final_ip}")
    print("----------------------------------------")
    status_code, http_rtt = make_http_request(final_ip, domain)
    print(status_code)
    print(f"RTT: {http_rtt:.2f} ms")


if __name__ == "__main__":
    main()

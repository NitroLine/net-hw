import argparse
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import *
import dnslib
import ipaddress
import multiprocessing
conf.L3socket = L3RawSocket
parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action="store_true",
                    help="increase output verbosity")
parser.add_argument("-g", "--guess", action="store_true",
                    help="guess protocol")
parser.add_argument("--timeout", type=float, default=2, metavar='TIME', required=False,
                    help="scan timeout in seconds (default=2)")
parser.add_argument("-j", "--num-threads", type=int, default=multiprocessing.cpu_count(), metavar='NUM', required=False,
                    help="threads count(default = cpu_count)")
parser.add_argument("ip_address", type=str, help="ip address of scanning object", metavar="IP_ADDRESS")
parser.add_argument("ports", type=str, help="ports and scanning protocols", nargs='*', default=['tcp', 'udp'],
                    metavar="{tcp|udp}[/[PORT|PORT-PORT]")
args = parser.parse_args()
if args.timeout <= 0:
    print("Timeout must be positive")
    exit(0)
if args.num_threads <= 0:
    print("Num threads must be positive")
    exit(0)
try:
    ipaddress.IPv4Address(args.ip_address)
except ipaddress.AddressValueError:
    print("Invalid ip address")
    exit(0)
dest_ip = args.ip_address
for_scan_on_udp = []
for_scan_on_tcp = []

dns_mess = b'\xee\xee\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03ns1\x06yandex\x02ru\x00\x00\x01\x00\x01'
dns_tcp_mess = b'\x00\x1f\xee\xee\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03ns1\x06yandex\x02ru\x00\x00\x01\x00\x01'
http_mess = b'GET / HTTP/1.1\nHost: localhost\n\n'


def parse_ports(ports=None):
    if ports is None or len(ports) == 0:
        yield range(1, 65536)
        return
    for ports_string in ports.split(','):
        parsed = ports_string.split('-')
        if len(parsed) > 1:
            port_range = range(int(parsed[0]), int(parsed[1]))
        else:
            port = int(parsed[0])
            port_range = range(port, port + 1)
        yield port_range


def scan_udp_ports(ports):
    if not ports:
        return
    packet = IP(dst=dest_ip) / UDP(sport=random.randint(10000, 65000), dport=ports) / DNS(dns_mess)
    answers, exp = sr(packet, timeout=args.timeout, verbose=0)
    for req, ans in answers:
        protocol = ''
        status = 'filtered'
        work_time = ''
        port = ans.sport
        if args.verbose:
            work_time = ' ' + str(round((ans.time - req.sent_time) * 1000, 1)) + 'ms'
        if ans.haslayer(UDP):
            status = 'open'
        elif ans.haslayer(ICMP) and ans[ICMP].code == 3:
            status = 'closed'
            port = req.dport
        if args.guess and status == 'open':
            protocol = ' -'
            if ans.haslayer(DNS):
                protocol = ' dns'
            elif raw(ans[Raw]) == raw(req[DNS]):
                protocol = ' echo'
        if status == 'open':
            print(f"UDP {port}{work_time}{protocol}")


def get_tcp_answer(message, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    s.connect((dest_ip, port))
    s.send(message)
    message = b''
    try:
        message = s.recv(1024)
    except socket.timeout:
        pass
    s.close()
    return message


def detect_tcp_protocol(port):
    message = get_tcp_answer(dns_tcp_mess, port)
    if message == dns_tcp_mess:
        return 'echo'
    try:
        dnslib.DNSRecord.parse(message[2:])
        return 'dns'
    except dnslib.DNSError:
        pass
    if 'SSH'.encode() in message:
        return 'ssh'
    message = get_tcp_answer(http_mess, port)
    if 'HTTP'.encode() in message:
        return 'http'
    if '220'.encode() in message:
        return 'smtp'
    return "-"


def scan_tcp_ports(ports):
    if not ports:
        return
    packet = IP(dst=dest_ip) / TCP(sport=random.randint(10000, 65000), dport=ports, flags="S")
    answers, exp = sr(packet, timeout=args.timeout, verbose=0)
    for req, ans in answers:
        protocol = ''
        status = 'filtered'
        work_time = ''
        if args.verbose:
            work_time = ' ' + str(round((ans.time - req.sent_time) * 1000, 1)) + 'ms'
        if ans.haslayer(TCP) and ans[TCP].flags == "SA":
            status = 'open'
        elif ans.haslayer(TCP) and (ans[TCP].flags == "RA" or ans[TCP].flags == "RS"):
            status = 'closed'
        if args.guess and status == 'open':
            protocol = ' ' + detect_tcp_protocol(req.dport)
        if status == 'open':
            print(f"TCP {req.dport}{work_time}{protocol}")


def split_and_scan(ports_for_scan, scan_method):
    ports_part = []
    for ports_range in ports_for_scan:
        for port in ports_range:
            ports_part.append(port)
            if len(ports_part) == args.num_threads:
                scan_method(ports_part)
                ports_part = []
    scan_method(ports_part)


for s in args.ports:
    parsed = s.split('/')
    if len(parsed) > 1:
        string_ports = parsed[1]
    else:
        string_ports = None
    try:
        ports = list(parse_ports(string_ports))
    except:
        print("Invalid PORTS format")
        exit(0)
    if parsed[0] == 'udp':
        for_scan_on_udp += ports
    elif parsed[0] == 'tcp':
        for_scan_on_tcp += ports

split_and_scan(for_scan_on_tcp, scan_tcp_ports)
split_and_scan(for_scan_on_udp, scan_udp_ports)

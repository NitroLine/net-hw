import random
from scapy.all import sr1
from scapy.layers.inet import IP, UDP, ICMP, TCP
import ipwhois
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action="store_true",
                    help="increase output verbosity")
parser.add_argument("-6", "--ipv6", action="store_true",
                    help="ipv6 support")
parser.add_argument("-t", "--timeout", type=float, default=2, metavar='TIME', required=False,
                    help="scan timeout in seconds (default=2)")
parser.add_argument("-c", "--count", type=int, default=64, metavar='NUM', required=False,
                    help="max ttl count (default=64)")
parser.add_argument("-n", "--max-request", type=int, default=3, metavar='NUM', required=False,
                    help="request count (default=3)")
parser.add_argument("ip_address", type=str, help="ip address of scanning object", metavar="IP_ADDRESS")
parser.add_argument("protocol", type=str, help="ip address of scanning object", metavar="PROTOCOL", choices=['tcp', 'udp', 'icmp'])
parser.add_argument('-p', "--port", type=int, help="port for traceroute", required=False)
args = parser.parse_args()

if args.protocol != 'icmp' and not args.port:
    print(f"For not icmp port (-p) needed")
    exit(-1)
if args.timeout <= 0:
    print("Timeout must be positive")
    exit(-1)

protocol_package = {'icmp': ICMP(),
                    'tcp': TCP(sport=random.randint(10000, 65000), dport=args.port),
                    'udp': UDP(sport=random.randint(10000, 65000), dport=args.port)}
protocol_package_v6 = {'icmp': ICMPv6EchoRequest(),
                    'tcp': TCP(sport=random.randint(10000, 65000), dport=args.port),
                    'udp': UDP(sport=random.randint(10000, 65000), dport=args.port)}
max_counter = args.max_request


def find_route(address: str):
    for i in range(1, args.count):
        for c in range(max_counter):
            if args.ipv6:
                package = IPv6(dst=address, hlim=i) / protocol_package_v6[args.protocol]
            else:
                package = IP(dst=address, ttl=i) / protocol_package[args.protocol]
            resp = sr1(package, verbose=0, timeout=args.timeout)
            if resp is not None:
                break
        else:
            print(i, '* *')
            continue
        who = ''
        if args.ipv6:
            layer = IPv6
        else:
            layer = IP
        if args.verbose:
            try:
                who = ipwhois.IPWhois(resp[layer].src).lookup_whois()['asn']
            except ipwhois.IPDefinedError:
                who = "Local"
        print(i, resp[layer].src, f'{round((resp.time - package.sent_time) * 1000, 2)}ms', who)
        if resp[layer].src == address:
            break


find_route(args.ip_address)

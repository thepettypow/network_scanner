#!/usr/bin/env python3
import logging
import argparse
import sys
from scapy.all import *
from socket import getservbyport

# Configure logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

def ping_scan(target):
    """Perform an ICMP ping scan to check if the host is up."""
    logging.info(f"Starting ping scan for {target}...")
    ans, _ = sr(IP(dst=target)/ICMP(), timeout=2, verbose=0)
    for _, received in ans:
        logging.info(f"Host {received.src} is up!")

def tcp_scan(target, ports, fast_mode=False):
    """Perform a TCP SYN scan on specified ports."""
    logging.info(f"Starting TCP port scan for {target}...")
    for port in ports:
        src_port = RandShort()
        response = sr1(IP(dst=target)/TCP(sport=src_port, dport=port, flags="S"), timeout=1, verbose=0)
        if response:
            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK received
                    service = getservbyport(port, "tcp") if not fast_mode else "unknown"
                    logging.info(f"Port {port} ({service}) is open.")
                    sr(IP(dst=target)/TCP(sport=src_port, dport=port, flags="R"), timeout=1, verbose=0)  # Send RST
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK received
                    logging.info(f"Port {port} is closed.")
        else:
            logging.info(f"Port {port} is filtered or host is down.")

def udp_scan(target, ports):
    """Perform a UDP scan on specified ports."""
    logging.info(f"Starting UDP port scan for {target}...")
    for port in ports:
        response = sr1(IP(dst=target)/UDP(dport=port), timeout=2, verbose=0)
        if response is None:
            logging.info(f"Port {port} is open or filtered.")
        elif response.haslayer(ICMP):
            if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]:
                logging.info(f"Port {port} is closed.")
            else:
                logging.info(f"Port {port} is open or filtered.")

def ping_sweep(subnet):
    """Perform a ping sweep on a subnet."""
    logging.info(f"Starting ping sweep for subnet {subnet}...")
    ans, _ = sr(IP(dst=subnet)/ICMP(), timeout=2, verbose=0)
    for _, received in ans:
        logging.info(f"Host {received.src} is up!")

def os_detection(target):
    """Detect the operating system using TTL values."""
    logging.info(f"Attempting OS detection for {target}...")
    response = sr1(IP(dst=target)/ICMP(), timeout=2, verbose=0)
    if response:
        ttl = response.ttl
        if ttl <= 64:
            logging.info(f"{target} is likely a Linux/Unix system.")
        elif ttl <= 128:
            logging.info(f"{target} is likely a Windows system.")
        else:
            logging.info(f"{target} has an unknown OS.")
    else:
        logging.info("OS detection failed. Host may be down.")

def full_port_scan(target):
    """Perform a full port scan from 1 to 65535."""
    logging.info(f"Starting full port scan for {target}...")
    ports = range(1, 65536)
    tcp_scan(target, ports, fast_mode=True)

def main():
    parser = argparse.ArgumentParser(description="Advanced Network Scanner with Python")
    parser.add_argument("target", help="Target IP address, subnet, or range")
    parser.add_argument("-p", "--ports", nargs="+", type=int, help="Ports to scan (e.g., 80 443 22)")
    parser.add_argument("--ping", action="store_true", help="Perform a ping scan")
    parser.add_argument("--tcp", action="store_true", help="Perform a TCP port scan")
    parser.add_argument("--udp", action="store_true", help="Perform a UDP port scan")
    parser.add_argument("--sweep", action="store_true", help="Perform a ping sweep (subnet required)")
    parser.add_argument("--os", action="store_true", help="Perform OS detection")
    parser.add_argument("--full", action="store_true", help="Perform a full port scan (1-65535)")
    args = parser.parse_args()

    if not any([args.ping, args.tcp, args.udp, args.sweep, args.os, args.full]):
        logging.error("Please specify at least one scan type (--ping, --tcp, --udp, --sweep, --os, --full).")
        sys.exit(1)

    if args.ping:
        ping_scan(args.target)

    if args.tcp:
        if not args.ports:
            logging.error("Please specify ports to scan with --ports.")
            sys.exit(1)
        tcp_scan(args.target, args.ports)

    if args.udp:
        if not args.ports:
            logging.error("Please specify ports to scan with --ports.")
            sys.exit(1)
        udp_scan(args.target, args.ports)

    if args.sweep:
        ping_sweep(args.target)

    if args.os:
        os_detection(args.target)

    if args.full:
        full_port_scan(args.target)

if __name__ == "__main__":
    main()


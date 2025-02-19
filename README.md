# Advanced Network Scanner

## Overview
This is an advanced Python-based network scanner that allows you to scan hosts and ports efficiently. The scanner supports multiple functionalities, including:
- **Ping Scan**: Checks if a host is online.
- **TCP Scan**: Performs a SYN scan to detect open ports.
- **UDP Scan**: Scans for open UDP ports.
- **Ping Sweep**: Scans a subnet to find active hosts.
- **OS Detection**: Attempts to determine the target OS using TTL values.
- **Full Port Scan**: Scans all 65,535 ports for open services.

## Requirements
- Python 3
- `scapy` library (install using `pip install scapy`)

## Usage
Run the script with different options depending on the scan type you need.

### Basic Commands

#### Ping Scan
```bash
python3 scanner.py --ping target_ip
```

#### TCP Scan
```bash
python3 scanner.py --tcp target_ip -p 22 80 443
```

#### UDP Scan
```bash
python3 scanner.py --udp target_ip -p 53 161
```

#### Ping Sweep (for subnet scanning)
```bash
python3 scanner.py --sweep 192.168.1.0/24
```

#### OS Detection
```bash
python3 scanner.py --os target_ip
```

#### Full Port Scan (1-65535)
```bash
python3 scanner.py --full target_ip
```

## Notes
- Ensure you have administrative privileges when running the script.
- Some ISPs and firewalls may block scan attempts.

## Disclaimer
This tool is intended for educational and ethical use only. Unauthorized scanning of networks without permission is illegal in many jurisdictions. The author assumes no responsibility for misuse.



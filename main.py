import socket
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor
import time
import sys

def tcp_connect_scan(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return True
        sock.close()
    except:
        pass
    return False

def udp_scan(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (ip, port))
        data, addr = sock.recvfrom(1024)
        return True
    except socket.timeout:
        return False
    except:
        return False
    finally:
        sock.close()

def scan_port(ip, port, timeout, scan_type):
    if scan_type == 'tcp':
        return tcp_connect_scan(ip, port, timeout)
    elif scan_type == 'udp':
        return udp_scan(ip, port, timeout)

def port_scan(ip, ports, timeout, scan_type, threads):
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, timeout, scan_type): port for port in ports}
        for future in threading.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
                    print(f"Port {port} is open")
            except Exception as exc:
                print(f'An error occurred while scanning port {port}: {exc}')
    return open_ports

def main():
    parser = argparse.ArgumentParser(description='Advanced Port Scanner')
    parser.add_argument('target', help='IP address to scan')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port range to scan (default: 1-1024)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Timeout for each port scan (default: 1.0)')
    parser.add_argument('-s', '--scan-type', choices=['tcp', 'udp'], default='tcp', help='Scan type (default: tcp)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads to use (default: 100)')
    args = parser.parse_args()

    ip = args.target
    timeout = args.timeout
    scan_type = args.scan_type
    threads = args.threads

    if '-' in args.ports:
        start_port, end_port = map(int, args.ports.split('-'))
        ports = range(start_port, end_port + 1)
    else:
        ports = map(int, args.ports.split(','))

    print(f"Starting {scan_type.upper()} scan on {ip}")
    start_time = time.time()
    
    open_ports = port_scan(ip, ports, timeout, scan_type, threads)
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\nScan completed in {duration:.2f} seconds")
    print(f"Open ports: {', '.join(map(str, open_ports))}")

if __name__ == "__main__":
    main()

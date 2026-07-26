#!/usr/bin/env python3

import socket
import threading
import queue
import argparse
import time
from datetime import datetime


class PortScanner:
    def __init__(self, target, start_port, end_port, threads=100, timeout=0.5):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout

        self.port_queue = queue.Queue()
        self.open_ports = []
        self.closed_ports = []
        self.lock = threading.Lock()

    def resolve_target(self):
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except socket.gaierror:
            print(f"[-] Unable to resolve {self.target}")
            return None

    def fill_queue(self):
        for port in range(self.start_port, self.end_port + 1):
            self.port_queue.put(port)

    def scan_port(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((ip, port))

            with self.lock:
                if result == 0:
                    self.open_ports.append(port)
                    print(f"[+] Port {port:<5} OPEN")
                else:
                    self.closed_ports.append(port)

        finally:
            sock.close()

    def worker(self, ip):
        while True:
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                break

            self.scan_port(ip, port)
            self.port_queue.task_done()

    def banner_grab(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            sock.connect((ip, port))
            banner = sock.recv(1024).decode(errors="ignore").strip()

            if banner:
                print(f"    Banner: {banner}")

            sock.close()

        except Exception:
            pass

    def print_summary(self, elapsed):
        print("\n========== SUMMARY ==========")
        print(f"Target: {self.target}")
        print(f"Elapsed: {elapsed:.2f} seconds")
        print(f"Open Ports: {len(self.open_ports)}")
        print(f"Closed Ports: {len(self.closed_ports)}")

        if self.open_ports:
            print("\nOpen Ports:")
            for port in sorted(self.open_ports):
                print(f"  - {port}")

        print("=============================\n")

    def save_results(self, filename):
        with open(filename, "w") as f:
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Date: {datetime.now()}\n\n")

            f.write("Open Ports\n")
            f.write("----------------\n")

            for port in sorted(self.open_ports):
                f.write(f"{port}\n")

        print(f"[+] Results saved to {filename}")

    def run(self):
        ip = self.resolve_target()

        if not ip:
            return

        print(f"[*] Target: {self.target}")
        print(f"[*] IP: {ip}")
        print(f"[*] Scanning ports {self.start_port}-{self.end_port}")
        print(f"[*] Threads: {self.threads}\n")

        self.fill_queue()

        start = time.time()

        workers = []

        for _ in range(self.threads):
            thread = threading.Thread(target=self.worker, args=(ip,))
            thread.start()
            workers.append(thread)

        for thread in workers:
            thread.join()

        elapsed = time.time() - start

        print()

        for port in sorted(self.open_ports):
            self.banner_grab(ip, port)

        self.print_summary(elapsed)

        self.save_results("scan_results.txt")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Educational Multithreaded TCP Port Scanner"
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "-s",
        "--start",
        default=1,
        type=int,
        help="Starting port"
    )

    parser.add_argument(
        "-e",
        "--end",
        default=1024,
        type=int,
        help="Ending port"
    )

    parser.add_argument(
        "-t",
        "--threads",
        default=100,
        type=int,
        help="Number of worker threads"
    )

    parser.add_argument(
        "--timeout",
        default=0.5,
        type=float,
        help="Socket timeout"
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    scanner = PortScanner(
        target=args.target,
        start_port=args.start,
        end_port=args.end,
        threads=args.threads,
        timeout=args.timeout
    )

    scanner.run()


if __name__ == "__main__":
    main()

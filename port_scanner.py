#!/usr/bin/env python3

import socket


def scan_port(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            print(f"[+] Port {port} OPEN")
        else:
            print(f"[-] Port {port} CLOSED")

        sock.close()

    except Exception as error:
        print(error)


target = input("Target IP: ")

for port in range(1, 100):
    scan_port(target, port)

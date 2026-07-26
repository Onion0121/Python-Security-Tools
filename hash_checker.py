#!/usr/bin/env python3

import hashlib


file = input("File path: ")

with open(file, "rb") as f:
    data = f.read()

hash_value = hashlib.sha256(data).hexdigest()

print("[+] SHA256:")
print(hash_value)

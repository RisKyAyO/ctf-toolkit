#!/usr/bin/env python3
"""
Multi-format encoder/decoder for CTF challenges.
"""
import base64
import codecs
import urllib.parse
import binascii
import argparse


def b64_encode(s: str) -> str: return base64.b64encode(s.encode()).decode()
def b64_decode(s: str) -> str: return base64.b64decode(s).decode()
def b32_encode(s: str) -> str: return base64.b32encode(s.encode()).decode()
def b32_decode(s: str) -> str: return base64.b32decode(s).decode()
def hex_encode(s: str) -> str: return s.encode().hex()
def hex_decode(s: str) -> str: return bytes.fromhex(s).decode()
def rot13(s: str) -> str: return codecs.encode(s, "rot_13")
def url_encode(s: str) -> str: return urllib.parse.quote(s)
def url_decode(s: str) -> str: return urllib.parse.unquote(s)
def binary_encode(s: str) -> str: return " ".join(format(ord(c), "08b") for c in s)
def binary_decode(s: str) -> str: return "".join(chr(int(b, 2)) for b in s.split())


OPERATIONS = {
    "b64e": b64_encode, "b64d": b64_decode,
    "b32e": b32_encode, "b32d": b32_decode,
    "hexe": hex_encode, "hexd": hex_decode,
    "rot13": rot13, "urle": url_encode, "urld": url_decode,
    "bine": binary_encode, "bind": binary_decode,
}


def main():
    parser = argparse.ArgumentParser(description="CTF Encoder/Decoder")
    parser.add_argument("--input", required=True, help="Input string")
    parser.add_argument("--op", required=True, choices=OPERATIONS.keys(),
                        help="Operation: b64e/d, b32e/d, hexe/d, rot13, urle/d, bine/d")
    args = parser.parse_args()
    try:
        result = OPERATIONS[args.op](args.input)
        print(f"[{args.op}] {result}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()

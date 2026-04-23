#!/usr/bin/env python3
"""
Hash identification, comparison and dictionary attack.
Usage: python hash_toolkit.py --hash <hash> [--wordlist rockyou.txt]
"""

import hashlib
import re
import argparse
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

HASH_PATTERNS = {
    r"^[a-f0-9]{32}$": ["MD5"],
    r"^[a-f0-9]{40}$": ["SHA-1"],
    r"^[a-f0-9]{56}$": ["SHA-224"],
    r"^[a-f0-9]{64}$": ["SHA-256"],
    r"^[a-f0-9]{96}$": ["SHA-384"],
    r"^[a-f0-9]{128}$": ["SHA-512"],
    r"^\$2[ayb]\$.{56}$": ["bcrypt"],
    r"^\$6\$.{8,}\$.{86}$": ["SHA-512 crypt"],
}

HASHLIB_MAP = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-224": "sha224",
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
}


def identify_hash(hash_str: str) -> list:
    """Identify possible hash types based on length and pattern."""
    candidates = []
    for pattern, types in HASH_PATTERNS.items():
        if re.match(pattern, hash_str.lower()):
            candidates.extend(types)
    return candidates or ["Unknown"]


def crack_hash(target_hash: str, hash_type: str, wordlist_path: str):
    """Dictionary attack against a hash."""
    algo = HASHLIB_MAP.get(hash_type)
    if not algo:
        print(f"{Fore.YELLOW}[-] Dictionary attack not supported for {hash_type}{Style.RESET_ALL}")
        return None

    from pathlib import Path
    wl = Path(wordlist_path)
    if not wl.exists():
        print(f"{Fore.RED}[-] Wordlist not found: {wordlist_path}{Style.RESET_ALL}")
        return None

    print(f"[+] Starting dictionary attack ({hash_type}) ...")
    checked = 0
    with open(wl, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            h = hashlib.new(algo, word.encode()).hexdigest()
            if h == target_hash.lower():
                return word
            checked += 1
            if checked % 100000 == 0:
                print(f"    {checked:,} candidates tested...", end="\r")
    return None


def main():
    parser = argparse.ArgumentParser(description="Hash Toolkit")
    parser.add_argument("--hash", required=True, help="Hash to analyse")
    parser.add_argument("--wordlist", help="Path to wordlist for dictionary attack")
    args = parser.parse_args()

    h = args.hash.strip()
    types = identify_hash(h)
    print(f"\n{Fore.CYAN}[+] Hash: {h}{Style.RESET_ALL}")
    print(f"[+] Possible types: {', '.join(types)}")

    if args.wordlist and types[0] != "Unknown":
        result = crack_hash(h, types[0], args.wordlist)
        if result:
            print(f"\n{Fore.GREEN}[+] CRACKED: {result}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[-] Not found in wordlist.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()

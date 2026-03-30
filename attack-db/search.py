#!/usr/bin/env python3
"""
Attack Database Search — Find attack patterns by keyword, category, or severity.

Usage:
    python3 search.py "prompt injection"
    python3 search.py --category command_injection
    python3 search.py --severity critical
    python3 search.py --list
    python3 search.py --stats
"""

import argparse
import json
import os
import sys

ATTACKS_DIR = os.path.join(os.path.dirname(__file__), 'attacks')

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

SEV_COLORS = {"critical": RED, "high": RED, "medium": YELLOW, "low": CYAN}


def load_all():
    """Load all attack patterns from JSON files."""
    patterns = []
    for root, dirs, files in os.walk(ATTACKS_DIR):
        for f in sorted(files):
            if f.endswith('.json'):
                with open(os.path.join(root, f)) as fh:
                    try:
                        patterns.append(json.load(fh))
                    except json.JSONDecodeError:
                        pass
    return patterns


def print_pattern(p, verbose=False):
    """Pretty-print one pattern."""
    sc = SEV_COLORS.get(p["severity"], YELLOW)
    print(f"  {BOLD}{p['id']}{RESET} — {p['name']}")
    print(f"  {sc}[{p['severity'].upper()}]{RESET} | {p['category']} | channels: {', '.join(p.get('channels', []))}")
    print(f"  {DIM}{p['description']}{RESET}")
    if verbose:
        print(f"  {DIM}Keywords: {len(p.get('keywords', []))} | Regex: {len(p.get('regex', []))}{RESET}")
        if p.get('examples', {}).get('malicious'):
            print(f"  {RED}Attack example: {p['examples']['malicious'][0][:80]}{RESET}")
        if p.get('examples', {}).get('benign'):
            print(f"  {GREEN}Safe example: {p['examples']['benign'][0][:80]}{RESET}")
    print()


def cmd_search(args):
    patterns = load_all()
    query = ' '.join(args.query).lower() if args.query else ''

    if args.category:
        patterns = [p for p in patterns if p['category'] == args.category]
    if args.severity:
        patterns = [p for p in patterns if p['severity'] == args.severity]
    if query:
        patterns = [p for p in patterns if
                    query in p['name'].lower() or
                    query in p['description'].lower() or
                    query in p['category'].lower() or
                    any(query in kw.lower() for kw in p.get('keywords', []))]

    if not patterns:
        print(f"\n  {DIM}No patterns found.{RESET}\n")
        return

    print(f"\n  {BOLD}Found {len(patterns)} pattern(s){RESET}\n")
    for p in patterns:
        print_pattern(p, verbose=args.verbose)


def cmd_list(args):
    patterns = load_all()
    print(f"\n  {BOLD}Attack Database — {len(patterns)} patterns{RESET}\n")
    for p in patterns:
        sc = SEV_COLORS.get(p["severity"], YELLOW)
        print(f"  {p['id']:12s} {sc}[{p['severity']:8s}]{RESET} {p['name']}")
    print()


def cmd_stats(args):
    patterns = load_all()
    cats = {}
    sevs = {}
    for p in patterns:
        cats[p['category']] = cats.get(p['category'], 0) + 1
        sevs[p['severity']] = sevs.get(p['severity'], 0) + 1

    total_kw = sum(len(p.get('keywords', [])) for p in patterns)
    total_rx = sum(len(p.get('regex', [])) for p in patterns)

    print(f"\n  {BOLD}Attack Database Stats{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")
    print(f"  Total patterns:   {CYAN}{len(patterns)}{RESET}")
    print(f"  Total keywords:   {CYAN}{total_kw}{RESET}")
    print(f"  Total regex:      {CYAN}{total_rx}{RESET}")
    print(f"\n  {BOLD}By Category:{RESET}")
    for cat, count in sorted(cats.items()):
        print(f"    {cat:25s} {count}")
    print(f"\n  {BOLD}By Severity:{RESET}")
    for sev in ['critical', 'high', 'medium', 'low']:
        if sev in sevs:
            sc = SEV_COLORS.get(sev, "")
            print(f"    {sc}{sev:25s} {sevs[sev]}{RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Search the GLASSES Attack Database")
    parser.add_argument("query", nargs="*", help="Search keywords")
    parser.add_argument("--category", "-c", help="Filter by category")
    parser.add_argument("--severity", "-s", help="Filter by severity")
    parser.add_argument("--list", "-l", action="store_true", help="List all patterns")
    parser.add_argument("--stats", action="store_true", help="Show database stats")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show examples")

    args = parser.parse_args()

    if args.stats:
        cmd_stats(args)
    elif args.list:
        cmd_list(args)
    else:
        cmd_search(args)


if __name__ == "__main__":
    main()

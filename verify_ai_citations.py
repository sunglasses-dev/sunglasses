#!/usr/bin/env python3
"""Verify AI agent traffic in your access logs against vendor published IP lists.

A user agent is a claim. Anyone can type ChatGPT-User into a request header.
The source IP is the evidence. OpenAI, Anthropic, DuckDuckGo and Perplexity
publish the IP ranges their fetchers really use. This script checks every
request that claims to be an AI agent against those lists and tells you which
were real, which were fake and which cannot be checked.

Written after we found 2,437 fake AI agent requests in one week of our own
logs, probing for AI coding agent credential files. Full story:
https://sunglasses.dev/reports/fake-ai-agents-credential-recon-august-2026

Usage:
    python3 verify_ai_citations.py access.log
    python3 verify_ai_citations.py --csv traffic.csv          # columns: ip,user_agent
    cat access.log | python3 verify_ai_citations.py -
    python3 verify_ai_citations.py access.log --detail        # per-IP breakdown

Stdlib only. No install. Reads combined/common log format or a two column CSV.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
import urllib.request

# Vendor list endpoints. Each fetcher UA maps to the list it must appear in.
VENDOR_LISTS = {
    "openai_user": "https://openai.com/chatgpt-user.json",
    "openai_search": "https://openai.com/searchbot.json",
    "openai_train": "https://openai.com/gptbot.json",
    "anthropic": "https://claude.com/crawling/bots.json",
    "duckduckgo": "https://duckduckgo.com/duckduckbot.json",
    "perplexity_bot": "https://www.perplexity.ai/perplexitybot.json",
    "perplexity_user": "https://www.perplexity.ai/perplexity-user.json",
}

# (label, UA regex, vendor list key or None when the vendor publishes no list)
UA_CLAIMS = [
    ("ChatGPT-User (answer time)", r"chatgpt-user", "openai_user"),
    ("OAI-SearchBot (index)", r"oai-searchbot", "openai_search"),
    ("GPTBot (training)", r"gptbot", "openai_train"),
    ("Claude-User (answer time)", r"claude-user", "anthropic"),
    ("Claude-SearchBot (index)", r"claude-searchbot", "anthropic"),
    ("ClaudeBot (training)", r"claudebot|claude-web|anthropic-ai", "anthropic"),
    ("DuckAssistBot (answer time)", r"duckassistbot", "duckduckgo"),
    ("DuckDuckBot (search)", r"duckduckbot", "duckduckgo"),
    ("Perplexity-User (answer time)", r"perplexity-user", "perplexity_user"),
    ("PerplexityBot (index)", r"perplexitybot", "perplexity_bot"),
    ("Amazonbot (no list published)", r"amazonbot", None),
    ("Cohere (no list published)", r"cohere-ai|cohere-training", None),
    ("Meta AI (no list published)", r"meta-externalagent|meta-externalfetcher", None),
]
UA_COMPILED = [(label, re.compile(rx, re.I), key) for label, rx, key in UA_CLAIMS]

# combined/common log format: IP is field 1, UA is the last quoted string
LOG_RX = re.compile(r'^(\S+) \S+ \S+ \[[^\]]*\] "[^"]*" \S+ \S+(?: "[^"]*")? "([^"]*)"')


def fetch_ranges(quiet: bool) -> dict[str, list]:
    nets: dict[str, list] = {}
    for key, url in VENDOR_LISTS.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "verify-ai-citations/1.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())
            prefixes: list[str] = []
            stack = [data]
            while stack:
                node = stack.pop()
                if isinstance(node, dict):
                    for k, v in node.items():
                        if k in ("ipv4Prefix", "ipv6Prefix") and isinstance(v, str):
                            prefixes.append(v)
                        else:
                            stack.append(v)
                elif isinstance(node, list):
                    stack.extend(node)
            nets[key] = [ipaddress.ip_network(p) for p in prefixes]
            if not quiet:
                print(f"  fetched {url} ({len(nets[key])} ranges)", file=sys.stderr)
        except Exception as exc:
            nets[key] = []
            print(f"  WARNING could not fetch {url}: {exc}. "
                  f"Claims needing it will score uncheckable, never verified.", file=sys.stderr)
    return nets


def in_ranges(ip: str, networks: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in networks if addr.version == n.version)


def iter_rows(path: str, is_csv: bool):
    handle = sys.stdin if path == "-" else open(path, encoding="utf-8", errors="replace")
    try:
        if is_csv:
            reader = csv.DictReader(handle)
            for row in reader:
                lowered = {k.lower().strip(): (v or "") for k, v in row.items()}
                ip = lowered.get("ip") or lowered.get("clientip") or lowered.get("client_ip") or ""
                ua = lowered.get("user_agent") or lowered.get("useragent") or lowered.get("ua") or ""
                if ip:
                    yield ip.strip(), ua
        else:
            for line in handle:
                m = LOG_RX.match(line)
                if m:
                    yield m.group(1), m.group(2)
    finally:
        if handle is not sys.stdin:
            handle.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Check claimed AI agent traffic against vendor published IP lists.")
    ap.add_argument("logfile", help="access log path, or - for stdin")
    ap.add_argument("--csv", action="store_true", help="input is CSV with ip and user_agent columns")
    ap.add_argument("--detail", action="store_true", help="print per-IP breakdown for fake traffic")
    ap.add_argument("--json", action="store_true", help="machine readable output")
    args = ap.parse_args()

    print("Fetching vendor IP lists...", file=sys.stderr)
    nets = fetch_ranges(quiet=args.json)

    tally: dict[str, dict[str, int]] = {}
    fake_ips: dict[str, dict[str, object]] = {}
    total_rows = 0
    for ip, ua in iter_rows(args.logfile, args.csv):
        total_rows += 1
        for label, rx, key in UA_COMPILED:
            if rx.search(ua):
                if key is None or not nets.get(key):
                    verdict = "uncheckable"
                elif in_ranges(ip, nets[key]):
                    verdict = "verified"
                else:
                    verdict = "fake"
                bucket = tally.setdefault(label, {"verified": 0, "fake": 0, "uncheckable": 0})
                bucket[verdict] += 1
                if verdict == "fake":
                    rec = fake_ips.setdefault(ip, {"n": 0, "claims": set()})
                    rec["n"] += 1
                    rec["claims"].add(label.split(" ")[0])
                break

    totals = {"verified": 0, "fake": 0, "uncheckable": 0}
    for bucket in tally.values():
        for k in totals:
            totals[k] += bucket[k]

    if args.json:
        print(json.dumps({
            "rows_read": total_rows, "totals": totals,
            "by_claim": tally,
            "fake_ips": {ip: {"requests": r["n"], "claims": sorted(r["claims"])}
                         for ip, r in fake_ips.items()},
        }, indent=2))
        return 0

    print(f"\nRead {total_rows} requests. {sum(totals.values())} claimed to be an AI agent.\n")
    width = max((len(l) for l in tally), default=20)
    print(f"{'claim':<{width}}  {'verified':>9} {'fake':>7} {'uncheckable':>12}")
    for label, b in sorted(tally.items(), key=lambda kv: -sum(kv[1].values())):
        print(f"{label:<{width}}  {b['verified']:>9} {b['fake']:>7} {b['uncheckable']:>12}")
    print(f"{'TOTAL':<{width}}  {totals['verified']:>9} {totals['fake']:>7} {totals['uncheckable']:>12}")

    if totals["fake"]:
        print(f"\n{totals['fake']} requests wore an AI vendor name from an address the vendor does not publish.")
        print("Those are not that vendor. Do not count them as AI citations.")
        multi = [ip for ip, r in fake_ips.items() if len(r["claims"]) > 1]
        if multi:
            print(f"{len(multi)} address(es) claimed to be MORE THAN ONE vendor. "
                  f"One machine cannot be several companies. That is a scanner.")
        if args.detail:
            print("\nfake traffic by IP:")
            for ip, r in sorted(fake_ips.items(), key=lambda kv: -kv[1]["n"]):
                print(f"  {ip:<40} {r['n']:>6}  claimed: {', '.join(sorted(r['claims']))}")
    if totals["uncheckable"]:
        print(f"\n{totals['uncheckable']} requests claim vendors with no published list. "
              f"Uncheckable is not the same as clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

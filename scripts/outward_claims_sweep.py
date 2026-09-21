"""Outward-claims sweep on the COMPOSED release notes, per the 9-20 07:22 ruling.

    python3 claims_sweep.py <checkout> <version>

Composes the notes exactly as git-ship does (section extract + DRAFT/PENDING
strip), then judges four may-not claims PER BULLET rather than per character
window. The window version of this sweep reported 3 hits and 2 of them were its
own: the condition sat in the same bullet, further away than the window reached.
A sweep that reports its own reach as a leak trains everyone to ignore it.

Exit 1 if any bullet makes a claim without its condition attached.
"""
import re, subprocess, sys, textwrap

checkout, ver = sys.argv[1], sys.argv[2]
raw = subprocess.run(
    ["awk", "-v", f"ver={ver}", '/^## \\[/{p=0} $0 ~ "^## \\\\["ver"\\\\]"{p=1;next} p',
     "CHANGELOG.md"], cwd=checkout, capture_output=True, text=True).stdout
notes = subprocess.run(
    ["awk", 'BEGIN{skip=0} /^> \\*\\*DRAFT\\.\\*\\*/{skip=1} skip&&/^[^>]/{skip=0} '
     '/^### PENDING/{pend=1;next} pend&&/^### /{pend=0} !skip&&!pend'],
    input=raw, capture_output=True, text=True).stdout

assert notes.strip(), f"no {ver} section in CHANGELOG.md"
leak = re.search(r"DRAFT|### PENDING|^## \[", notes, re.M)
if leak:
    print(f"SCAFFOLDING LEAK: {leak.group(0)!r} survived the strip"); sys.exit(1)

RULES = [
 ("R1 unqualified tool-result scanning",
  r"\b(scan|scans|scanning|scanned|inspect\w*|detect\w*)\b[^.]{0,120}\btool[- ]result",
  r"approv|credential lane|not general|NOT general|once |two states|nothing is inspected"),
 ("R2 proxy claim without its condition",
  r"\bproxy\b[^.]{0,160}\b(enforc\w+|withhold\w*|block\w*|mediat\w+|protect\w*|inspect\w*)",
  r"approv|APPROVAL_REQUIRED|inert|not a supported surface|nothing is inspected"
  r"|not protection|before a human|two states"),
 ("R3 comparison with another tool",
  r"pipelock|than any other tool|better than|outperform\w*|compared (with|to) (other|any)",
  r"no comparison|not claimed"),
 ("R4 general tool-result inspection",
  r"general(ly)? inspect\w*|inspect\w* (of )?(everything|all)\b|all tool results",
  r"\bnot\b|\bnever\b"),
]
bullets = [b for b in re.split(r"\n\s*\n", notes) if b.strip()]
print(f"composed {ver}: {len(raw.splitlines())} raw -> {len(notes.splitlines())} stripped, "
      f"{notes.count('### ')} subsections, {len(bullets)} bullets")
total = 0
for name, claim, qual in RULES:
    hits = [(i, b) for i, b in enumerate(bullets)
            if re.search(claim, b, re.I) and not re.search(qual, b, re.I)]
    print(f"\n{name}: {len(hits)} unqualified")
    total += len(hits)
    for i, b in hits:
        m = re.search(claim, b, re.I)
        print(f"  bullet[{i}] match {m.group(0)[:70]!r}")
        print(textwrap.fill(" ".join(b.split())[:500], 74,
                            initial_indent="    ", subsequent_indent="    "))
print(f"\nTOTAL unqualified claims: {total}")
sys.exit(1 if total else 0)

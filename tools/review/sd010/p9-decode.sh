#!/bin/zsh
# P9 the decoder probe (T9 RULING 32): what JSON, Python and YAML make of each
# spelling, written independently of the grammar module, beside where the
# matrix stands on it. Round 10's probes run by default; add your own as
# fenced ```decode blocks in VERDICT.md.
# EXPECT: this wrapper states NO counts. Only codepoints and names are
# EXPECT: printed, and the EXIT CODE is the verdict: 0 agree, 1 disagree.
D=$(cd $(dirname $0)/.. && pwd)
PYTHONUNBUFFERED=1 python3 "$D/probes/_p9.py" "$D"

#!/bin/zsh
# P1 THE SPINE: every sibling's regex and keywords must equal its parent's, and
# its channel must be exactly [api_response]. #170's law, made checkable.
# EXPECT: this wrapper states NO counts. The driver prints what it derived and
# EXPECT: its EXIT CODE is the verdict.
D=$(cd $(dirname $0)/.. && pwd); PYTHONUNBUFFERED=1 python3 "$D/probes/_p1.py" "$D"

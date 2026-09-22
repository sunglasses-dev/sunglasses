#!/bin/zsh
# P3 DO THEY DETECT. The probe the broken generation would have failed: it
# produced fourteen siblings that loaded, counted, and matched NOTHING.
# EXPECT: no counts stated. Exit non-zero if any sibling is SILENT. A sibling
# EXPECT: detected but dedup-shadowed is covered, not silent -- the raw finding
# EXPECT: list and the consumer surface answer different questions.
D=$(cd $(dirname $0)/.. && pwd); PYTHONUNBUFFERED=1 python3 "$D/probes/_p3.py" "$D"

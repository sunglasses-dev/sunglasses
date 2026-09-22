#!/bin/zsh
# P7 the case-CONSTRUCTING runner: builds its own inputs from orthogonal axes
# so the review is not limited to fixtures the author already thought of.
# EXPECT: this wrapper states NO counts. The driver prints what it constructed
# EXPECT: beside what it found, and its EXIT CODE is the verdict.
# Axes: quoting value boundary key all   (default all). Pass several.
# Nothing here writes a file; only counts, axis labels and rule ids are printed.
D=$(cd $(dirname $0)/.. && pwd)
PYTHONUNBUFFERED=1 python3 "$D/probes/_p7.py" "$D" "$@"

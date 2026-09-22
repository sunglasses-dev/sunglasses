#!/bin/zsh
# P8 the (?-i:) scope across EVERY evaluation mode -- the item rounds 2 and 3
# both left UNMEASURED. Modes: plain guarded windowed anchored (default all).
# EXPECT: this wrapper states NO counts. The driver prints the mode it INTENDED
# EXPECT: and the mode the engine actually LANDED in, read back from the engine
# EXPECT: itself; a mismatch is reported UNMEASURED, never scored. Exit 0 pass.
D=$(cd $(dirname $0)/.. && pwd)
PYTHONUNBUFFERED=1 python3 "$D/probes/_p8.py" "$D" "$@"

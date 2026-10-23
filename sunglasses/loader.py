"""
SUNGLASSES Database Loader — Loads attack patterns for the engine.

By default it returns the built-in pattern set; given a directory it reads the
attack-db/ JSON files and converts them into the format the engine expects.
"""

import copy
import json
import os


def load_attack_db(db_path: str = None) -> list:
    """Load attack patterns in the format the engine expects.

    With no path this returns every built-in pattern, the same set the engine
    runs by default, so an engine built from it behaves like SunglassesEngine().
    Each record has a ``keywords`` list, empty when the rule defines none.
    With a path it reads the JSON files below that directory (the repo's
    attack-db/attacks layout).
    """
    if db_path is None:
        from .patterns import PATTERNS
        # Copies, so a caller who edits a record cannot change the live rules.
        records = copy.deepcopy(PATTERNS)
        # Every record has always carried a keyword list here; a built-in rule that
        # defines none gets its own empty one.
        for record in records:
            record.setdefault("keywords", [])
        return records

    if not os.path.isdir(db_path):
        return []

    patterns = []
    for root, dirs, files in os.walk(db_path):
        for f in sorted(files):
            if not f.endswith('.json'):
                continue
            filepath = os.path.join(root, f)
            try:
                with open(filepath) as fh:
                    data = json.load(fh)

                # Convert JSON format to engine format
                pattern = {
                    "id": data["id"],
                    "name": data["name"],
                    "category": data["category"],
                    "severity": data["severity"],
                    "channel": data.get("channels", []),
                    "description": data.get("description", ""),
                    "keywords": data.get("keywords", []),
                }
                if data.get("regex"):
                    pattern["regex"] = data["regex"]

                patterns.append(pattern)
            except (json.JSONDecodeError, KeyError):
                pass

    return patterns

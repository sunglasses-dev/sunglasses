"""
GLASSES Database Loader — Loads attack patterns from JSON files.

Reads the attack-db/ directory and converts JSON patterns into the format
the engine expects. This is what connects the "fat database" to the "thin filter."
"""

import json
import os


def load_attack_db(db_path: str = None) -> list:
    """Load all attack patterns from JSON files in the attack-db directory."""
    if db_path is None:
        db_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'attack-db', 'attacks'
        )

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

#!/usr/bin/env python3
"""
Export patterns.py → attack-db/ JSON files

Single source of truth: sunglasses/patterns.py
This script generates the attack-db/ JSON files from it.
Run after every pattern update to keep them in sync.

Usage:
    python scripts/export_patterns_to_attack_db.py

Safety: READ-ONLY on patterns.py. Only writes to attack-db/attacks/
"""
import json
import os
import re
import sys
import datetime

# Add parent dir to path so we can import sunglasses
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sunglasses.patterns import PATTERNS

# Category mapping: internal category name → folder name
CATEGORY_FOLDERS = {
    "prompt_injection": "prompt-injection",
    "exfiltration": "data-exfiltration",
    "hidden_instruction": "hidden-instruction",
    "command_injection": "command-injection",
    "secret_detection": "secret-detection",
    "memory_poisoning": "memory-poisoning",
    "social_engineering": "social-engineering",
    "parasitic_injection": "prompt-injection",
    "agent_workflow": "agent-workflow",
    "encoded_payload": "encoded-payload",
    "dns_tunneling": "dns-tunneling",
    "supply_chain": "supply-chain",
    "c2_indicator": "c2-indicator",
    "mcp_threat": "mcp-threat",
}

def slugify(text):
    """Convert name to filename slug."""
    text = text.lower().strip()
    text = re.sub(r'[^a-z0-9]+', '-', text)
    text = text.strip('-')
    return text[:60]

def get_folder(category):
    """Map category to folder name."""
    return CATEGORY_FOLDERS.get(category, category.replace("_", "-"))

def export():
    base_dir = os.path.join(os.path.dirname(__file__), "..", "attack-db", "attacks")

    # Track stats
    stats = {}
    total = 0

    for pattern in PATTERNS:
        pid = pattern.get("id", "UNKNOWN")
        name = pattern.get("name", "unnamed")
        category = pattern.get("category", "uncategorized")
        folder = get_folder(category)
        folder_path = os.path.join(base_dir, folder)
        os.makedirs(folder_path, exist_ok=True)

        # Build JSON entry matching existing format
        entry = {
            "id": pid,
            "name": name,
            "version": "1.0",
            "category": category,
            "severity": pattern.get("severity", "medium"),
            "channels": pattern.get("channel", ["message"]),
            "description": pattern.get("description", ""),
            "keywords": pattern.get("keywords", []),
            "regex": [r if isinstance(r, str) else str(r) for r in pattern.get("regex", [])],
            "examples": {
                "malicious": [],
                "benign": []
            },
            "references": [],
            "contributed_by": "Sunglasses Team",
            "date_added": "2026-04-08",
            "source": f"patterns.py:{pid}"
        }

        # Write file
        slug = slugify(name)
        filename = f"{pid}-{slug}.json"
        filepath = os.path.join(folder_path, filename)

        with open(filepath, "w") as f:
            json.dump(entry, f, indent=2)

        # Stats
        stats[folder] = stats.get(folder, 0) + 1
        total += 1

    # Write integrity manifest
    manifest = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "source": "sunglasses/patterns.py",
        "total_patterns": total,
        "categories": stats,
        "generator": "scripts/export_patterns_to_attack_db.py"
    }

    manifest_path = os.path.join(base_dir, "..", "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    # Print summary
    print(f"Exported {total} patterns to attack-db/attacks/")
    print(f"Categories: {len(stats)}")
    for folder, count in sorted(stats.items()):
        print(f"  {folder}: {count}")
    print(f"Manifest: attack-db/manifest.json")

if __name__ == "__main__":
    export()

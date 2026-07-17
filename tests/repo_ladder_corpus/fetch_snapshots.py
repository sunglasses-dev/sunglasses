#!/usr/bin/env python3
"""Snapshot the agent-input surfaces of famous, known-legit repos into
tests/repo_ladder_corpus/<owner__repo>/ so the repo-ladder gate
(test_repo_ladder_corpus.py) runs offline and deterministically.

Re-run manually to refresh snapshots (they are committed, not fetched in CI):
    python3 tests/repo_ladder_corpus/fetch_snapshots.py
"""
import os
import urllib.request

# Mirrors the worker's AGENT_SURFACES list (sunglasses-worker/src/github.js).
SURFACES = [
    "README.md", "CLAUDE.md", "AGENTS.md", "GEMINI.md",
    ".cursorrules", ".clinerules", ".windsurfrules",
    ".github/copilot-instructions.md",
    "mcp.json", ".mcp.json", ".vscode/mcp.json", "llms.txt",
]

# Famous, legitimate repos — the exact kind a sponsor or troll scans first.
# Our own repos are exempt (mirror test: they document attack patterns).
REPOS = [
    "mempalace/mempalace",
    "AgriciDaniel/claude-seo",
    "coreyhaines31/marketingskills",
    "ComposioHQ/awesome-claude-skills",
    "Imbad0202/academic-research-skills",
    "pytorch/pytorch",
    "openai/openai-python",
    "run-llama/llama_index",
    "trufflesecurity/trufflehog",
    "modelcontextprotocol/servers",
    "langchain-ai/langchain",
    "huggingface/transformers",
]

HERE = os.path.dirname(os.path.abspath(__file__))


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sunglasses-corpus"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception:
        return None


def main():
    for slug in REPOS:
        owner, repo = slug.split("/")
        outdir = os.path.join(HERE, f"{owner}__{repo}")
        got = 0
        for surface in SURFACES:
            text = None
            for branch in ("main", "master"):
                text = fetch(f"https://raw.githubusercontent.com/{slug}/{branch}/{surface}")
                if text is not None:
                    break
            if text is None:
                continue
            os.makedirs(outdir, exist_ok=True)
            safe = surface.replace("/", "__")
            with open(os.path.join(outdir, safe), "w") as f:
                f.write(text[:100_000])  # match the demo's 100KB cap
            got += 1
        print(f"{slug}: {got} surfaces")


if __name__ == "__main__":
    main()

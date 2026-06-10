"""
SUNGLASSES — SARIF 2.1.0 output emitter.

Converts a ScanResult into a SARIF Log so findings can be piped into
GitHub Advanced Security, code scanning dashboards, and CI/CD gates.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

Usage:
    from sunglasses.engine import SunglassesEngine
    from sunglasses.sarif import to_sarif

    engine = SunglassesEngine()
    result = engine.scan("ignore previous instructions")
    sarif_log = to_sarif([result], source="inline")
    print(json.dumps(sarif_log, indent=2))
"""

import json
from typing import Iterable, Optional

from . import __version__

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_TOOL_URI = "https://sunglasses.dev"
_TOOL_REPO = "https://github.com/sunglasses-dev/sunglasses"

# Map a finding's category -> the live /patterns/<chapter-slug> page that
# documents it. Mirrors CHAPTER_MAP in build-patterns-page.py (the patterns-page
# generator). Findings whose category isn't grouped into a chapter page fall back
# to the /patterns hub. Both targets are guaranteed-live (200) — this replaces the
# old per-finding-id helpUri that always 404'd (only chapter pages exist, not
# /patterns/<FINDING_ID>), which was breaking the GitHub code-scanning "Learn more"
# links. Keep in sync if chapters are added/renamed.
_CATEGORY_TO_CHAPTER = {
    "prompt_injection": "prompt-injection",
    "indirect_prompt_injection": "prompt-injection",
    "hidden_instruction": "prompt-injection",
    "jailbreak_evasion": "prompt-injection",
    "prompt_extraction": "prompt-injection",
    "prompt_leak": "prompt-injection",
    "parasitic_injection": "prompt-injection",
    "context_flooding": "prompt-injection",
    "retrieval_poisoning": "prompt-injection",
    "mcp_threat": "mcp-tool-handoff-abuse",
    "tool_poisoning": "mcp-tool-handoff-abuse",
    "tool_metadata_smuggling": "mcp-tool-handoff-abuse",
    "tool_chain_race": "mcp-tool-handoff-abuse",
    "tool_output_poisoning": "mcp-tool-handoff-abuse",
    "provenance_chain": "callback-redirect-trust-drift",
    "provenance_chain_fracture": "callback-redirect-trust-drift",
    "agent_contract_poisoning": "callback-redirect-trust-drift",
    "exfiltration": "outbound-endpoint-control-c2-drift",
    "ssrf": "outbound-endpoint-control-c2-drift",
    "dns_tunneling": "outbound-endpoint-control-c2-drift",
    "c2_indicator": "outbound-endpoint-control-c2-drift",
    "secret_detection": "outbound-endpoint-control-c2-drift",
    "policy_scope_redefinition": "policy-scope-redefinition",
    "authorization_bypass": "policy-scope-redefinition",
    "auth_bypass": "policy-scope-redefinition",
    "privilege_escalation": "policy-scope-redefinition",
    "approval_graph_poisoning": "policy-scope-redefinition",
    "state_sync_poisoning": "state-sync-poisoning",
    "cross_agent_injection": "state-sync-poisoning",
    "memory_poisoning": "memory-persistence-poisoning",
    "memory_eviction_rehydration": "memory-persistence-poisoning",
    "supply_chain": "package-dependency-registry-trust-abuse",
    "ui_injection": "browser-agent-navigation-link-safety-abuse",
    "social_engineering_ui": "browser-agent-navigation-link-safety-abuse",
    "social_engineering": "browser-agent-navigation-link-safety-abuse",
    "identity_phishing": "browser-agent-navigation-link-safety-abuse",
    "agent_workflow_security": "agent-workflow-publish-path-abuse",
    "agent_workflow": "agent-workflow-publish-path-abuse",
    "agent_security": "agent-workflow-publish-path-abuse",
    "discovery_file_poisoning": "discovery-file-poisoning",
    "agent_instruction_file_poisoning": "discovery-file-poisoning",
    "identity_discovery_poisoning": "discovery-file-poisoning",
}


def _help_uri(finding: dict) -> str:
    """Return a guaranteed-live docs URL for a finding: its chapter page if the
    category maps to one, else the /patterns hub. Never points at a 404."""
    slug = _CATEGORY_TO_CHAPTER.get(finding.get("category", ""))
    return f"{_TOOL_URI}/patterns/{slug}" if slug else f"{_TOOL_URI}/patterns"


# Severity mapping: SUNGLASSES severities -> SARIF levels.
# SARIF levels: "none", "note", "warning", "error".
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "review": "note",
    "none": "none",
}

# SARIF security-severity: numeric score (0.0-10.0) used by code scanning UIs.
_SEVERITY_TO_SECURITY_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "review": "2.0",
}


def _build_rule(finding: dict) -> dict:
    """Build a SARIF rule (reportingDescriptor) from a finding."""
    severity = finding.get("severity", "medium")
    return {
        "id": finding["id"],
        "name": finding.get("name", finding["id"]),
        "shortDescription": {
            "text": finding.get("name", finding["id"]),
        },
        "fullDescription": {
            "text": finding.get("reason") or finding.get("description") or finding.get("name", finding["id"]),
        },
        "helpUri": _help_uri(finding),
        "properties": {
            "category": finding.get("category", "unknown"),
            "sunglasses_severity": severity,
            "security-severity": _SEVERITY_TO_SECURITY_SCORE.get(severity, "5.0"),
            "tags": [
                "security",
                "ai-agent-security",
                f"category:{finding.get('category', 'unknown')}",
            ],
        },
        "defaultConfiguration": {
            "level": _SEVERITY_TO_LEVEL.get(severity, "warning"),
        },
    }


def _build_result(finding: dict, artifact_uri: str, artifact_index: int) -> dict:
    """Build a SARIF result from a single finding."""
    severity = finding.get("severity", "medium")
    matched = finding.get("matched_text", "")
    return {
        "ruleId": finding["id"],
        "level": _SEVERITY_TO_LEVEL.get(severity, "warning"),
        "message": {
            "text": finding.get("reason")
            or finding.get("description")
            or f"{finding.get('name', finding['id'])} detected"
            + (f": \"{matched}\"" if matched else ""),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                        "index": artifact_index,
                    },
                }
            }
        ],
        "properties": {
            "category": finding.get("category", "unknown"),
            "sunglasses_severity": severity,
            "security-severity": _SEVERITY_TO_SECURITY_SCORE.get(severity, "5.0"),
            "matched_text": matched[:200],  # truncate for safety
            "decision": None,  # filled in per-run
        },
    }


def to_sarif(
    results: Iterable,
    source: str = "inline",
    artifact_uri: Optional[str] = None,
) -> dict:
    """
    Convert one or more ScanResult objects into a SARIF 2.1.0 log.

    Args:
        results: iterable of ScanResult instances.
        source: human-readable label for where the content came from
                ("inline", a filename, a repo URL, etc).
        artifact_uri: optional override for the SARIF artifact URI.
                      Defaults to `source` if it looks like a path/URL,
                      otherwise "input:inline".

    Returns:
        A dict representing a complete SARIF log. Serialize with json.dumps().
    """
    results = list(results)

    if artifact_uri is None:
        if source.startswith(("http://", "https://", "file://", "/")) or source.endswith(
            (".txt", ".md", ".py", ".js", ".json", ".html", ".yml", ".yaml")
        ):
            artifact_uri = source
        else:
            artifact_uri = f"input:{source}"

    # Collect unique rules across all results.
    rules_by_id: dict = {}
    for r in results:
        for f in r.findings:
            if f["id"] not in rules_by_id:
                rules_by_id[f["id"]] = _build_rule(f)

    # Build results array.
    sarif_results = []
    for r in results:
        for f in r.findings:
            res = _build_result(f, artifact_uri=artifact_uri, artifact_index=0)
            res["properties"]["decision"] = r.decision
            res["properties"]["channel"] = r.channel
            res["properties"]["event_id"] = r.event_id
            res["properties"]["latency_ms"] = r.latency_ms
            sarif_results.append(res)

    # Artifact entry (the thing we scanned).
    artifact = {
        "location": {"uri": artifact_uri},
        "roles": ["analysisTarget"],
    }

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sunglasses",
                        "fullName": "Sunglasses — AI Agent Input Filter",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": _TOOL_URI,
                        "downloadUri": _TOOL_REPO,
                        "shortDescription": {
                            "text": "Pattern-level semantic detection for AI agent inputs, outputs, and tool metadata.",
                        },
                        "rules": list(rules_by_id.values()),
                    }
                },
                "artifacts": [artifact],
                "results": sarif_results,
                "columnKind": "utf16CodeUnits",
            }
        ],
    }


def to_sarif_json(results, source: str = "inline", indent: int = 2) -> str:
    """Convenience: return SARIF as a formatted JSON string."""
    return json.dumps(to_sarif(results, source=source), indent=indent)

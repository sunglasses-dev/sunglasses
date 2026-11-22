"""The waiver file for the speed gate only shrinks.

FROZEN is the list of rule ids the waiver file may hold. A rule added to the waiver file turns the first test red, so a
rule that reads slowly is bounded in its rule and not waived. When a later change takes a rule out of the waiver file, the
same change takes its id out of this list, and the diff of both files shows it.
"""
import json
import pathlib

FROZEN = frozenset([
    "GLS-AB-003", "GLS-AIFP-010", "GLS-ALP-005", "GLS-APIP-004",
    "GLS-APIP-007", "GLS-AW-010", "GLS-AW-012", "GLS-CAI-259",
    "GLS-CF-248", "GLS-CICD-004", "GLS-DFP-002", "GLS-DFP-004",
    "GLS-DFP-014", "GLS-DFP-040", "GLS-DFP-044", "GLS-DFP-048",
    "GLS-DFP-055", "GLS-DFP-069", "GLS-DFP-108", "GLS-DFP-109",
    "GLS-DFP-140", "GLS-DFP-142", "GLS-DS-001", "GLS-EX-010",
    "GLS-EX-030", "GLS-IDP-003", "GLS-IDP-005", "GLS-IDP-011",
    "GLS-IP-006", "GLS-IU-533", "GLS-MCP-030", "GLS-MCP-057",
    "GLS-MCP-APT-209", "GLS-MCP-POISON-201", "GLS-MER-235", "GLS-MER-568",
    "GLS-MM-AUDIO-206", "GLS-MRC-458", "GLS-PCF-459", "GLS-PFX-001",
    "GLS-PFX-247", "GLS-RMP-002", "GLS-RP-278", "GLS-RP-457",
    "GLS-SCHEMA-LEAK-215", "GLS-SDH-001", "GLS-SI-001", "GLS-SPI-001", "GLS-SSRF-008",
    "GLS-TOP-637",
])


def _waivers():
    return json.loads((pathlib.Path(__file__).parent / "pattern_perf_waivers.json").read_text())


def test_the_waiver_file_holds_no_rule_that_is_not_in_the_frozen_list():
    extra = sorted(set(_waivers()) - FROZEN)
    assert not extra, f"a rule was added to the waiver file: {extra}"


def test_the_frozen_list_holds_no_rule_the_waiver_file_has_dropped():
    stale = sorted(FROZEN - set(_waivers()))
    assert not stale, f"a rule left the waiver file and stays in the frozen list: {stale}"


def test_the_concealment_action_rule_with_a_start_key_is_not_waived():
    assert "GLS-PI-015" not in _waivers()

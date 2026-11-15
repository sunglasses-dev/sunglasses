"""The pin for sunglasses/_floor_quiet.py: the rule ids that keep no guard-floor copy, written out here.

Two tests read this file: tests/test_floor_quiet.py checks the shipped list against it, and
tests/test_guard_floor.py excuses exactly these ids from the "a guard word never makes an allow" walk.
A rule joins or leaves the list only by editing the list and this pin in the same change.
"""

QUIET_IDS = (
    "GLS-AIFP-002", "GLS-AIFP-003", "GLS-AIFP-006", "GLS-APIP-001", "GLS-APIP-002", "GLS-APIP-011",
    "GLS-AW-603", "GLS-AW-611", "GLS-AW-616", "GLS-AW-619", "GLS-AW-625", "GLS-AW-654",
    "GLS-AW-681", "GLS-AW-697", "GLS-AW-724", "GLS-AW-731", "GLS-AW-744", "GLS-BMP-001", "GLS-BMP-002",
    "GLS-BMP-003", "GLS-BMP-004", "GLS-BMP-005", "GLS-BMP-007", "GLS-BMP-009", "GLS-CICD-008", "GLS-DBSL-004",
    "GLS-DFP-009", "GLS-DFP-017", "GLS-DFP-018", "GLS-DFP-019", "GLS-DFP-034", "GLS-DFP-037", "GLS-DFP-038",
    "GLS-DFP-039", "GLS-DFP-040", "GLS-DFP-043", "GLS-DFP-056", "GLS-DFP-057", "GLS-DFP-063", "GLS-DFP-064",
    "GLS-DFP-071", "GLS-DFP-075", "GLS-DFP-090", "GLS-DFP-096", "GLS-DFP-135", "GLS-DOAS-001", "GLS-DOAS-004",
    "GLS-IDP-009", "GLS-IDP-016", "GLS-IP-004", "GLS-MCP-015", "GLS-MECH-006", "GLS-MP-014", "GLS-MR-001",
    "GLS-MR-006", "GLS-RMP-001", "GLS-RP-567", "GLS-SCAP-002", "GLS-SCAP-005", "GLS-SMP-010",
    "GLS-SMP-011", "GLS-SMP-023",
)

REVIEWED_IDS = (
    "GLS-AW-654",
)

QUIET_COUNT = 62

# Rules whose floor copy is matched per window (FLOOR_WINDOWED in sunglasses/_floor_quiet.py).
WINDOWED_IDS = (
    "GLS-AW-679", "GLS-MR-039",
)

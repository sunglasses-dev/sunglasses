"""Rules that keep no guard-floor copy.

A rule whose pattern opens with a guard (a negative lookahead for words such as "defensive" or "fixed") is
normally given a floor copy: the same rule without its guards, one severity step lower, that fires when a guard
word sits in the text. A rule listed here is given none; its own pattern, guards included, is all it has.

Each entry is (rule id, reason):

  "wide"      the guard-free form of the rule matches ordinary text. Measured on the tuning texts only: it had
              two or more findings there (real scan findings together with raw-view matches).
  "reviewed"  a reviewed ordinary file matched the rule's floor copy. The rule stays listed until it is tightened.

The list is data. The tuning texts live on one machine and the script that recomputes the list stays there;
tests/test_floor_quiet.py pins the ids and the size in the repository. A rule leaves the list when its
guard-free form is quiet on ordinary text again; delete its line and update the pin in the same change.

A second list holds the rules whose floor copy is matched one window at a time instead of over the whole text
(FLOOR_WINDOWED). Their regexes open with a "^" and then lookaheads that read to the end, so over a whole
document the groups could sit thousands of characters apart; per window (the engine's co-occurrence window)
they must sit together, as in an attack text. The regex text of the rule and of its copy is unchanged.
"""

FLOOR_QUIET = (
    ("GLS-AIFP-002", "wide"),
    ("GLS-AIFP-003", "wide"),
    ("GLS-AIFP-006", "wide"),
    ("GLS-APIP-001", "wide"),
    ("GLS-APIP-002", "wide"),
    ("GLS-APIP-011", "wide"),
    ("GLS-AW-603", "wide"),
    ("GLS-AW-611", "wide"),
    ("GLS-AW-616", "wide"),
    ("GLS-AW-619", "wide"),
    ("GLS-AW-625", "wide"),
    ("GLS-AW-654", "reviewed"),
    ("GLS-AW-681", "wide"),
    ("GLS-AW-697", "wide"),
    ("GLS-AW-724", "wide"),
    ("GLS-AW-731", "wide"),
    ("GLS-AW-744", "wide"),
    ("GLS-BMP-001", "wide"),
    ("GLS-BMP-002", "wide"),
    ("GLS-BMP-003", "wide"),
    ("GLS-BMP-004", "wide"),
    ("GLS-BMP-005", "wide"),
    ("GLS-BMP-007", "wide"),
    ("GLS-BMP-009", "wide"),
    ("GLS-CICD-008", "wide"),
    ("GLS-DBSL-004", "wide"),
    ("GLS-DFP-009", "wide"),
    ("GLS-DFP-017", "wide"),
    ("GLS-DFP-018", "wide"),
    ("GLS-DFP-019", "wide"),
    ("GLS-DFP-034", "wide"),
    ("GLS-DFP-037", "wide"),
    ("GLS-DFP-038", "wide"),
    ("GLS-DFP-039", "wide"),
    ("GLS-DFP-040", "wide"),
    ("GLS-DFP-043", "wide"),
    ("GLS-DFP-056", "wide"),
    ("GLS-DFP-057", "wide"),
    ("GLS-DFP-063", "wide"),
    ("GLS-DFP-064", "wide"),
    ("GLS-DFP-071", "wide"),
    ("GLS-DFP-075", "wide"),
    ("GLS-DFP-090", "wide"),
    ("GLS-DFP-096", "wide"),
    ("GLS-DFP-135", "wide"),
    ("GLS-DOAS-001", "wide"),
    ("GLS-DOAS-004", "wide"),
    ("GLS-IDP-009", "wide"),
    ("GLS-IDP-016", "wide"),
    ("GLS-IP-004", "wide"),
    ("GLS-MCP-015", "wide"),
    ("GLS-MECH-006", "wide"),
    ("GLS-MP-014", "wide"),
    ("GLS-MR-001", "wide"),
    ("GLS-MR-006", "wide"),
    ("GLS-RMP-001", "wide"),
    ("GLS-RP-567", "wide"),
    ("GLS-SCAP-002", "wide"),
    ("GLS-SCAP-005", "wide"),
    ("GLS-SMP-010", "wide"),
    ("GLS-SMP-011", "wide"),
    ("GLS-SMP-023", "wide"),
)

FLOOR_QUIET_IDS = frozenset(rule_id for rule_id, _reason in FLOOR_QUIET)

# The floor copy of these rules is matched per co-occurrence window (see above). Pinned in
# tests/_floor_quiet_pin.py; a rule joins or leaves only by editing this and the pin together.
FLOOR_WINDOWED = (
    "GLS-AW-679",
    "GLS-MR-039",
)

FLOOR_WINDOWED_IDS = frozenset(FLOOR_WINDOWED)

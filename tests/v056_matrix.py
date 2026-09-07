"""The v0.5.6 acceptance SPACE, as data.

Rounds 1 and 2 of this repair fixed the surfaces a reviewer happened to sample,
and round 2's review found the same defect in the next five samples. Sampling
was the problem. This module enumerates the space instead: every public surface
crossed with every input state, each cell carrying the outcome it must produce.

It is imported by two things and written by hand once:
  * ``tests/test_v056_matrix.py`` -- one generated test per cell;
  * ``tools/gen_v056_matrix_table.py`` -- the published case table.
Both read THIS file, so the table cannot drift from what the tests assert. A
cell that is legitimately impossible on a surface is recorded as N/A with the
reason, never dropped -- an omitted cell and a covered cell look identical in a
table, which is how a sampled suite reads as an exhaustive one.

OUTCOME vocabulary (the assertions live in the test module):

  clean              exit 0 · threat_found F · inspection_complete T · is_clean T
  threat             exit 1 · threat_found T · inspection_complete T · is_clean F
  threat_incomplete  exit 1 · threat_found T · inspection_complete F · is_clean F
  incomplete         exit 3 · threat_found F · inspection_complete F · is_clean F
  operational        exit 2 · one error document · MCP isError true · no verdict

`threat_incomplete` is the cell this release exists for: a finding and a
coverage failure are independent facts, and the code used to let the first one
manufacture the second.
"""

# --- outcomes -------------------------------------------------------------

OUTCOMES = {
    "clean": {
        "exit": 0, "threat_found": False, "inspection_complete": True,
        "is_clean": True, "is_error": False,
    },
    "threat": {
        "exit": 1, "threat_found": True, "inspection_complete": True,
        "is_clean": False, "is_error": False,
    },
    "threat_incomplete": {
        "exit": 1, "threat_found": True, "inspection_complete": False,
        "is_clean": False, "is_error": False,
    },
    "incomplete": {
        "exit": 3, "threat_found": False, "inspection_complete": False,
        "is_clean": False, "is_error": False,
    },
    "operational": {
        "exit": 2, "threat_found": None, "inspection_complete": None,
        "is_clean": False, "is_error": True,
    },
}

# --- states ---------------------------------------------------------------

STATES = [
    ("clean",             "clean", "ordinary content, fully readable"),
    ("finding",           "finding", "a pattern fires, fully readable"),
    ("incomplete_clean",  "incomplete, no finding", "part unread, nothing found in the rest"),
    ("incomplete_finding","incomplete + finding", "a finding AND part of the input unread"),
    ("unreadable",        "unreadable", "exists, cannot be opened (mode 000)"),
    ("missing",           "missing", "path does not exist"),
    ("missing_dependency","missing decoder", "readable media, no decoder installed"),
    ("truncated_finding", "truncated + finding", "over the 1 MiB cap, finding in the read part"),
]

# --- surfaces -------------------------------------------------------------
# formats: the output shapes this surface must produce a single document in.

SURFACES = [
    ("cli_file",            "cli", "CLI `scan --file`",             ("human", "json", "sarif")),
    ("cli_text",            "cli", "CLI `scan --text`",             ("human", "json", "sarif")),
    ("cli_stdin",           "cli", "CLI `scan --stdin`",            ("human", "json", "sarif")),
    ("cli_repo",            "cli", "CLI `scan --repo`",             ("human", "json", "sarif")),
    ("cli_deep",            "cli", "CLI `scan --deep`",             ("human", "json", "sarif")),
    ("lib_scan_fast",       "lib", "`scan_fast()`",                 ("dict",)),
    ("lib_scan_auto_false", "lib", "`scan_auto(allow_deep=False)`", ("dict",)),
    ("lib_scan_auto_true",  "lib", "`scan_auto(allow_deep=True)`",  ("dict",)),
    ("lib_scan_email",      "lib", "`scan_email()`",                ("dict",)),
    ("lib_scan_deep",       "lib", "`scan_deep()`",                 ("dict",)),
    ("mcp_scan_text",       "mcp", "MCP `scan_text`",               ("mcp",)),
    ("mcp_scan_file_false", "mcp", "MCP `scan_file` deep=false",    ("mcp",)),
    ("mcp_scan_file_true",  "mcp", "MCP `scan_file` deep=true",     ("mcp",)),
]

NA = "N/A"

# Reasons are load-bearing: each one is a claim that the cell cannot exist, and
# a reviewer is entitled to check it.
_TEXT_SURFACE_NA = {
    "incomplete_finding": (NA, "a string surface's only incompleteness is the size cap; "
                               "that cell is `truncated + finding`"),
    "unreadable":         (NA, "no file is opened on a string surface"),
    "missing":            (NA, "no path is resolved on a string surface"),
    "missing_dependency": (NA, "no extractor runs on a string surface"),
}

MATRIX = {}

# A cell can be asserted AND carry a caveat. NOTES is for behaviour that is
# truthful but differs from a sibling surface: hiding that in an N/A would be a
# lie, and silently asserting it would let the divergence go unrecorded.
NOTES = {}


def _row(surface, cells):
    for state, value in cells.items():
        MATRIX[(surface, state)] = value


_row("cli_file", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",          # a ZIP we do not extract
    "incomplete_finding": "threat_incomplete", # extractors disabled: raw bytes hit, coverage lost
    "unreadable": "operational", "missing": "operational",
    "missing_dependency": "incomplete",        # audio without --deep
    "truncated_finding": "threat_incomplete",
})

_ARGV_NA = (NA, "an over-cap input cannot reach `--text`: ARG_MAX is 1 MiB, exactly the "
                "scan cap, so the OS refuses the exec before the scanner sees it "
                "(verified: getconf ARG_MAX = 1048576). `--stdin` carries these two cells")

_row("cli_text", dict({
    "clean": "clean", "finding": "threat",
    "incomplete_clean": _ARGV_NA,
    "truncated_finding": _ARGV_NA,
}, **_TEXT_SURFACE_NA))

_row("cli_stdin", dict({
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "truncated_finding": "threat_incomplete",
}, **_TEXT_SURFACE_NA))

_row("cli_repo", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    "unreadable": (NA, "`--repo` scans a fresh clone and git carries only the exec bit, "
                       "so an unreadable member cannot survive the clone"),
    "missing": "operational",                  # clone failure
    "missing_dependency": "incomplete",        # a media file in the tree, never transcribed
    "truncated_finding": "incomplete",
})

NOTES[("cli_repo", "truncated_finding")] = (
    "SURFACE DIVERGENCE, recorded not fixed. The repo walker SKIPS a file over the "
    "1 MB limit and names it as not inspected (exit 3), where `--file` scans the "
    "first MiB and reports truncated + finding (exit 1). So an injection in the "
    "first KB of an oversized file is found by `--file` and missed by `--repo`. "
    "Both surfaces report their coverage honestly, which is why this is a gap and "
    "not a false clean. Unifying them changes what the walker reads and is v0.6 "
    "work, not a round-3 change; see KNOWN_VERSION_GAPS.md."
)

_row("cli_deep", {
    # clean / finding / incomplete_* use the test-only extraction seam: the
    # AudioExtractor is replaced in a driver subprocess, engine + CLI + serializer
    # run unmodified. Production code has no switch for this.
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",  # <- ASTRA R4: the coverage-erasing cell
    "unreadable": "operational", "missing": "operational",
    "missing_dependency": "incomplete",
    "truncated_finding": (NA, "the deep path scans a transcript produced under the cap; "
                              "truncation is covered on the file and string surfaces"),
})

_row("lib_scan_fast", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    "unreadable": "operational", "missing": "operational",
    "missing_dependency": "incomplete",
    "truncated_finding": "threat_incomplete",
})

_row("lib_scan_auto_false", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    "unreadable": "operational", "missing": "operational",
    "missing_dependency": "incomplete",        # the needs_deep_scan document
    "truncated_finding": "threat_incomplete",
})

_row("lib_scan_auto_true", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    "unreadable": "operational", "missing": "operational",
    "missing_dependency": "incomplete",        # routed to deep, no decoder present
    "truncated_finding": "threat_incomplete",
})

_row("lib_scan_email", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    "unreadable": "incomplete",                # one bad attachment, the rest still scanned
    "missing": "incomplete",
    "missing_dependency": "incomplete",        # <- ASTRA R1: the deferred attachment
    "truncated_finding": "threat_incomplete",
})

_row("lib_scan_deep", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    "unreadable": "operational", "missing": "operational",
    "missing_dependency": "incomplete",
    "truncated_finding": (NA, "see cli_deep: the transcript is produced under the cap"),
})

_row("mcp_scan_text", dict({
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "truncated_finding": "threat_incomplete",
}, **_TEXT_SURFACE_NA))

_row("mcp_scan_file_false", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    "unreadable": "operational", "missing": "operational",
    "missing_dependency": "incomplete",
    "truncated_finding": "threat_incomplete",
})

_row("mcp_scan_file_true", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    "unreadable": "operational",               # <- ASTRA R2: was isError:false
    "missing": "operational",
    "missing_dependency": "incomplete",        # <- ASTRA R1: was an axis-free document
    "truncated_finding": "threat_incomplete",
})


def cells():
    """Every (surface, state) pair in declaration order."""
    for sid, group, label, formats in SURFACES:
        for state, _slabel, _sdesc in STATES:
            yield sid, group, label, formats, state, MATRIX[(sid, state)]


def is_na(value) -> bool:
    return isinstance(value, tuple) and value[0] == NA


def coverage_counts():
    total = len(SURFACES) * len(STATES)
    na = sum(1 for *_x, value in cells() if is_na(value))
    return {"total": total, "asserted": total - na, "na": na}


# Every declared cell must exist; a missing key is a hole in the space.
_missing = [(s[0], st[0]) for s in SURFACES for st in STATES
            if (s[0], st[0]) not in MATRIX]
if _missing:  # pragma: no cover - import-time guard
    raise AssertionError(f"matrix has undeclared cells: {_missing}")

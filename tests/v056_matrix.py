"""The v0.5.6 acceptance SPACE, as data.

Rounds 1 and 2 of this repair fixed the surfaces a reviewer happened to sample,
and round 2's review found the same defect in the next five samples. So round 3
stopped sampling and enumerated the space instead.

ROUND 4 rewrites this module after ASTRA's third review, which accepted the table
as regression data and rejected it as a completeness argument. Three things were
wrong, and all three are the same mistake in different clothes -- a DECLARATION
was standing in for an ASSERTION:

  1. Missing surfaces. `engine.scan`, `engine.scan_file`, `scanner.scan_text`, the
     five extractor `scan_*` convenience functions, the three retained helpers,
     positional CLI input, the console-script leg and the real stdio MCP transport
     all produce results and had no rows. Two of them (`scan_image`, `scan_audio`)
     turned out to be carrying live false-clean bugs, which is exactly what a
     surface with no row buys you.
  2. N/A used as a coverage argument. Five reasons claimed a state was IMPOSSIBLE
     when it was merely untested (deep truncation, deep parser failure, repo
     unreadability). ASTRA produced runtime counterexamples for three and a source
     mechanism for two. Those five are now asserted. The N/A that survive are
     narrower, and each says what KIND of claim it is.
  3. States that existed and were not enumerated: a non-regular input (FIFO), a
     byte stream that does not decode, and empty content.

The vocabulary is now explicit, because "N/A" was doing four different jobs:

  * an OUTCOME string      -- the cell is asserted, and this is what must happen.
  * ``Alias(state, why)``  -- the cell is asserted, and its INPUT is the same
                              input another state already describes. It runs; the
                              label stops it from reading as extra coverage.
  * ``NotApplicable(why)`` -- the state cannot be constructed on this surface, and
                              the reason is a checkable claim about the surface's
                              interface, not about our test inventory.
  * ``EQUIVALENCE``        -- a separate map. A wrapper surface must produce the
                              SAME document as the surface it wraps; the test runs
                              BOTH and compares. Naming an equivalence is not
                              claiming one, so it is proven by execution.

It is imported by two things and written by hand once:
  * ``tests/test_v056_matrix.py`` -- one generated test per cell;
  * ``tools/gen_v056_matrix_table.py`` -- the published case table.
Both read THIS file, so the table cannot drift from what the tests assert. What
the table CANNOT do is prove the tests assert anything, which is why the test
module now carries mutation cases: for every outcome, a response with its coverage
evidence stripped must make the cell assertion FAIL.

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


# What KIND of claim an N/A reason is. Declared, never inferred: the round-3
# reasons ASTRA rejected all read like impossibility claims and were really "we
# did not test this", and no amount of reading the prose separates those two --
# only saying which one you are making does. Anything not on this list is not a
# reason, it is a shrug.
NA_CLAIMS = {
    # a property of THIS SURFACE'S API, checkable against the signature/source
    "interface": "the surface's own interface makes the state unreachable",
    # a property of the FORMAT's specification, checkable against that spec
    "format": "the input format's specification makes the state impossible",
    # a property of the STORAGE layer, checkable by trying it
    "storage": "the storage layer cannot represent the input this state needs",
    # true of THIS MACHINE, not of the software. ASTRA accepted the ARG_MAX
    # reason only on these terms, so the limit travels with the cell.
    "host": "true of this host's limits, not of the software",
}


class NotApplicable:
    """This state cannot be constructed on this surface, and here is why.

    ``claim`` names what KIND of argument the reason is, because "N/A" was being
    used for four different arguments and a reviewer could not tell which one was
    being made. ``why`` then has to substantiate that kind: an ``interface`` claim
    points at this surface's signature or source, a ``format`` claim at the format
    spec, a ``host`` claim says HOST-SCOPED out loud.

    ASTRA rejected five round-3 reasons for claiming a state was IMPOSSIBLE when it
    was merely untested. Those five are asserted cells now, and this field exists so
    the same slippage cannot be smuggled back in as confident prose.
    """

    kind = "N/A"

    def __init__(self, why, claim="interface"):
        if claim not in NA_CLAIMS:  # pragma: no cover - import-time guard
            raise AssertionError(
                f"unknown N/A claim kind {claim!r}; must be one of {sorted(NA_CLAIMS)}")
        self.why = why
        self.claim = claim

    @property
    def scope(self):  # pragma: no cover - kept for the table generator's older name
        return self.claim

    def __repr__(self):
        return f"NotApplicable({self.claim}: {self.why[:40]!r})"


class Alias:
    """Asserted, but its input is the same input another state already describes.

    ASTRA: "Aliased string partial-finding states can be represented by
    `truncated_finding`, but should be labeled aliases rather than nonexistent
    states." So the cell RUNS -- the alias target's input is fed to this surface
    and the outcome asserted -- and the label keeps it from being counted as an
    independent piece of evidence.
    """

    kind = "ALIAS"

    def __init__(self, state, why):
        self.state = state
        self.why = why

    def __repr__(self):
        return f"Alias({self.state!r})"


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
    ("corrupt_parser_fail","corrupt (parser fails)", "readable bytes whose format parser gives up"),
    # --- round 4 ---
    ("nonregular",        "not a regular file", "FIFO/socket/device/directory at the input path"),
    ("undecodable",       "bytes do not decode", "a byte stream that is not valid UTF-8"),
    ("empty",             "empty", "a VALID input of this format that legitimately "
                                   "carries no content (0-byte text file, blank image, "
                                   "silent audio) -- read in full, nothing there"),
]

# --- surfaces -------------------------------------------------------------
# formats: the output shapes this surface must produce a single document in.

SURFACES = [
    # CLI
    ("cli_file",            "cli", "CLI `scan --file`",             ("human", "json", "sarif")),
    ("cli_positional",      "cli", "CLI `scan <path>`",             ("human", "json", "sarif")),
    ("cli_console",         "cli", "`sunglasses` console script",   ("json",)),
    ("cli_text",            "cli", "CLI `scan --text`",             ("human", "json", "sarif")),
    ("cli_stdin",           "cli", "CLI `scan --stdin`",            ("human", "json", "sarif")),
    ("cli_repo",            "cli", "CLI `scan --repo`",             ("human", "json", "sarif")),
    ("cli_deep",            "cli", "CLI `scan --deep`",             ("human", "json", "sarif")),
    # library -- entry points
    ("lib_engine_scan",     "lib", "`SunglassesEngine.scan()`",     ("dict",)),
    ("lib_engine_scan_file","lib", "`SunglassesEngine.scan_file()`",("dict",)),
    ("lib_scanner_scan_text","lib","`SunglassesScanner.scan_text()`",("dict",)),
    ("lib_scan_fast",       "lib", "`scan_fast()`",                 ("dict",)),
    ("lib_scan_auto_false", "lib", "`scan_auto(allow_deep=False)`", ("dict",)),
    ("lib_scan_auto_true",  "lib", "`scan_auto(allow_deep=True)`",  ("dict",)),
    ("lib_scan_email",      "lib", "`scan_email()`",                ("dict",)),
    ("lib_scan_deep",       "lib", "`scan_deep()`",                 ("dict",)),
    # library -- the three retained helpers
    ("lib_helper_image",    "lib", "`_scan_image_fast()`",          ("dict",)),
    ("lib_helper_pdf",      "lib", "`_scan_pdf()`",                 ("dict",)),
    ("lib_helper_text",     "lib", "`_scan_text_file()`",           ("dict",)),
    # library -- the five public extractor convenience functions
    ("lib_conv_image",      "lib", "`extractors.image.scan_image()`", ("dict",)),
    ("lib_conv_pdf",        "lib", "`extractors.pdf.scan_pdf()`",   ("dict",)),
    ("lib_conv_qr",         "lib", "`extractors.qr.scan_qr()`",     ("dict",)),
    ("lib_conv_audio",      "lib", "`extractors.audio.scan_audio()`", ("dict",)),
    ("lib_conv_video",      "lib", "`extractors.video.scan_video()`", ("dict",)),
    # library -- the normalizer boundary itself
    ("lib_normalize",       "lib", "`result.normalize()`",          ("dict",)),
    # MCP
    ("mcp_scan_text",       "mcp", "MCP `scan_text`",               ("mcp",)),
    ("mcp_scan_file_false", "mcp", "MCP `scan_file` deep=false",    ("mcp",)),
    ("mcp_scan_file_true",  "mcp", "MCP `scan_file` deep=true",     ("mcp",)),
    ("mcp_stdio",           "mcp", "MCP over real stdio JSON-RPC",  ("wire",)),
]

MATRIX = {}

# A cell can be asserted AND carry a caveat. NOTES is for behaviour that is
# truthful but differs from a sibling surface: hiding that in an N/A would be a
# lie, and silently asserting it would let the divergence go unrecorded.
NOTES = {}

# A wrapper surface must produce the same document as what it wraps. The test runs
# BOTH and compares the canonical axes -- an equivalence that is claimed rather
# than executed is the thing ASTRA refused to sign.
EQUIVALENCE = {}


def _row(surface, cells):
    for state, value in cells.items():
        MATRIX[(surface, state)] = value


# =========================================================================
# reasons, written once and shared, so a reviewer checks each claim once
# =========================================================================

_NO_PATH = "this surface's input parameter is a string of content; no path is " \
           "resolved and no file is opened, so there is nothing to be missing, " \
           "unreadable, non-regular or of the wrong file type"
_NO_PARSER = "no format parser runs on this surface: the content arrives as text " \
             "and goes straight to the engine"
_STR_PARAM = "the parameter is already a `str`; byte-to-text decoding happened in " \
             "the transport above this surface (see cli_stdin/undecodable)"

_TEXT_ALIAS_INCFIND = Alias(
    "truncated_finding",
    "on a string surface the only way to lose coverage is the size cap, so "
    "'incomplete + finding' and 'truncated + finding' are the SAME input; asserted "
    "here under the alias rather than declared impossible")

_ARGV_HOST = NotApplicable(
    "an over-cap input cannot reach `--text`: this host's ARG_MAX is 1,048,576 "
    "bytes -- exactly the scan cap -- so execve() fails with E2BIG before the "
    "scanner runs. HOST-SCOPED: true of this machine, not of every OS or of a "
    "caller-configured cap. `--stdin` carries these two cells on every host",
    claim="host")


def _text_surface(extra):
    """The states a content-string surface can and cannot host."""
    base = {
        "incomplete_finding": _TEXT_ALIAS_INCFIND,
        "unreadable":         NotApplicable(_NO_PATH),
        "missing":            NotApplicable(_NO_PATH),
        "missing_dependency": NotApplicable(
            "no extractor and no decoder runs on this surface; content arrives "
            "already extracted"),
        "corrupt_parser_fail": NotApplicable(_NO_PARSER),
        "nonregular":         NotApplicable(_NO_PATH),
        "undecodable":        NotApplicable(_STR_PARAM),
    }
    base.update(extra)
    return base


def _file_surface(extra=None):
    """The default answers for a surface that takes a filesystem path."""
    base = {
        "clean": "clean",
        "finding": "threat",
        "incomplete_clean": "incomplete",          # a ZIP we do not extract
        "incomplete_finding": "threat_incomplete", # extractors disabled: raw bytes hit
        "unreadable": "operational",
        "missing": "operational",
        "missing_dependency": "incomplete",        # media without --deep
        "truncated_finding": "threat_incomplete",
        "corrupt_parser_fail": "incomplete",
        "nonregular": "operational",
        "undecodable": "incomplete",               # bytes that do not decode are unread
        "empty": "clean",                          # 0 of 0 bytes read IS complete
    }
    base.update(extra or {})
    return base


# =========================================================================
# CLI
# =========================================================================

_row("cli_file", _file_surface())

# `scan <path>` -- the positional leg, which auto-promotes an existing path to a
# file scan. ASTRA listed it as a missing surface; it is a wrapper, so it is
# asserted AND compared against `--file` on the same input.
_row("cli_positional", _file_surface({
    "missing": "operational",   # path-shaped and absent -> usage error, not a scan
}))
for _state in ("clean", "finding", "incomplete_clean", "missing_dependency",
               "corrupt_parser_fail", "undecodable", "empty"):
    EQUIVALENCE[("cli_positional", _state)] = "cli_file"

# The console entry point. Same code, different launcher -- and "different
# launcher" is precisely where a packaging bug lives, so it is executed rather
# than asserted by name. JSON only: the document is the comparison.
_row("cli_console", _file_surface())
for _state in ("clean", "finding", "incomplete_clean", "incomplete_finding",
               "unreadable", "missing", "missing_dependency", "truncated_finding",
               "corrupt_parser_fail", "nonregular", "undecodable", "empty"):
    EQUIVALENCE[("cli_console", _state)] = "cli_file"

_row("cli_text", _text_surface({
    "clean": "clean", "finding": "threat",
    "incomplete_clean": _ARGV_HOST,
    "truncated_finding": _ARGV_HOST,
    "empty": "clean",
}))
MATRIX[("cli_text", "incomplete_finding")] = _ARGV_HOST

_row("cli_stdin", _text_surface({
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "truncated_finding": "threat_incomplete",
    # The one text surface that owns a byte->text boundary, which is why the
    # `undecodable` state exists at all (ASTRA F5).
    "undecodable": "operational",
    "empty": "clean",
}))

_row("cli_repo", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    # ASTRA REJECTED the round-3 N/A here and supplied the counterexample: a
    # committed SYMLINK to a mode-000 target survives a fresh clone. Asserted now.
    "unreadable": "incomplete",
    "missing": "operational",                  # clone failure
    "missing_dependency": "incomplete",        # a media file in the tree
    "truncated_finding": "incomplete",
    "corrupt_parser_fail": "incomplete",
    "nonregular": NotApplicable(
        "git's object model stores regular files, symlinks and directories only; "
        "a FIFO, socket or device node cannot be committed, so no clone can "
        "contain one. Verified by attempting `git add` on a FIFO fixture",
        claim="storage"),
    "undecodable": "incomplete",               # a committed non-UTF-8 file
    "empty": "clean",                          # a committed empty file
})

NOTES[("cli_repo", "truncated_finding")] = (
    "SURFACE DIVERGENCE, recorded not fixed. The repo walker SKIPS a file over the "
    "1 MB limit and names it as not inspected (exit 3), where `--file` scans the "
    "first MiB and reports truncated + finding (exit 1). So an injection in the "
    "first KB of an oversized file is found by `--file` and missed by `--repo`. "
    "Both surfaces report their coverage honestly, which is why this is a gap and "
    "not a false clean. Unifying them changes what the walker reads and is v0.6 "
    "work; see KNOWN_VERSION_GAPS.md. ASTRA independently reproduced both halves "
    "and ratified the deferral."
)
NOTES[("cli_repo", "unreadable")] = (
    "The member is a committed symlink whose target is mode 000 -- ASTRA's "
    "counterexample to the round-3 N/A. The walker names it and the repo scan "
    "returns 3, NOT the operational 2 that `--file` returns for the same target: "
    "one unreadable member does not make a whole tree unscannable."
)

_row("cli_deep", {
    # clean / finding / incomplete_* / truncated / parser-fail use the test-only
    # extraction seam: the AudioExtractor is replaced in a driver subprocess, and
    # the engine, aggregate, scanner, normalizer, CLI and serializer all run
    # unmodified. Production code has no switch for this.
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    "unreadable": "operational", "missing": "operational",
    "missing_dependency": "incomplete",
    # ASTRA REJECTED the round-3 N/A: the transcript producer has no cap, so a
    # transcript longer than the engine's 1 MiB cap truncates the CHILD, and the
    # deep aggregate used to drop that. Asserted now, at the DEFAULT cap.
    "truncated_finding": "threat_incomplete",
    # ASTRA REJECTED the round-3 N/A ("indistinguishable from a missing decoder").
    # A decoder CAN fail after its dependencies load, and the handler for that
    # already exists at extractors/audio.py `_transcribe`'s except branch. The
    # seam raises from inside that handler's try, so the mapping is executed.
    "corrupt_parser_fail": "incomplete",
    "nonregular": "operational",
    "undecodable": Alias(
        "corrupt_parser_fail",
        "on the deep path 'these bytes did not decode' IS the decoder-failure "
        "state -- both arrive through the same `_transcribe` except branch -- so "
        "it is asserted under that alias rather than declared impossible"),
    "empty": "clean",                          # decoder ran, produced no speech
})
NOTES[("cli_deep", "corrupt_parser_fail")] = (
    "EXPLICIT EQUIVALENCE MAPPING, as ASTRA required. The decoder-failure fixture "
    "raises inside `AudioExtractor._transcribe`, the same except branch a real "
    "Whisper/ffmpeg failure lands in, and the assertion additionally requires the "
    "warning to NAME the decoder failure -- so it is distinguishable from the "
    "missing-decoder document, whose warning names the missing install. No "
    "successful Whisper run and no real Whisper corruption is claimed."
)

# =========================================================================
# library -- entry points
# =========================================================================

_row("lib_engine_scan", _text_surface({
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "truncated_finding": "threat_incomplete",
    "empty": "clean",
}))

_row("lib_scanner_scan_text", _text_surface({
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "truncated_finding": "threat_incomplete",
    "empty": "clean",
}))
for _state in ("clean", "finding", "incomplete_clean", "truncated_finding", "empty"):
    EQUIVALENCE[("lib_scanner_scan_text", _state)] = "lib_engine_scan"

_row("lib_engine_scan_file", _file_surface())
_row("lib_scan_fast", _file_surface())
for _state in ("clean", "finding", "incomplete_clean", "missing_dependency",
               "corrupt_parser_fail", "undecodable", "empty"):
    EQUIVALENCE[("lib_engine_scan_file", _state)] = "lib_scan_fast"

_row("lib_scan_auto_false", _file_surface({
    "missing_dependency": "incomplete",        # the needs_deep_scan document
}))
_row("lib_scan_auto_true", _file_surface({
    "missing_dependency": "incomplete",        # routed to deep, no decoder present
}))

_row("lib_scan_email", _file_surface({
    # The attachment states: one bad attachment must not take down the email, and
    # must not be reported as a clean email either.
    "unreadable": "incomplete",
    "missing": "incomplete",
    "nonregular": "incomplete",
    "missing_dependency": "incomplete",        # <- ASTRA R1: the deferred attachment
}))
NOTES[("lib_scan_email", "unreadable")] = (
    "DELIBERATE DIVERGENCE from the file surfaces. `scan_fast` raises operational "
    "on a mode-000 path; the email aggregate catches it per attachment, keeps "
    "scanning the body and the other attachments, and folds the failure in as lost "
    "coverage. An email is not unscannable because one of its parts is."
)

_row("lib_scan_deep", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    "unreadable": "operational", "missing": "operational",
    "missing_dependency": "incomplete",
    "truncated_finding": "threat_incomplete",  # <- ASTRA REJECT of the round-3 N/A
    "corrupt_parser_fail": "incomplete",       # <- ASTRA REJECT of the round-3 N/A
    "nonregular": "operational",
    "undecodable": Alias("corrupt_parser_fail",
                         "see cli_deep: the same `_transcribe` except branch"),
    "empty": "clean",
})

# =========================================================================
# library -- the three retained helpers
#
# `scan_fast` routes everything through extractors.dispatch, so nothing in the
# package calls these. They are still public methods on the public scanner class,
# the brief retains them as supported API, and ASTRA cited their repair as release
# evidence -- which is exactly why they get rows. `_scan_image_fast` was carrying
# a live false clean (F2) that no CLI path could have exposed.
# =========================================================================

_HELPER_WRONG_TYPE = NotApplicable(
    "this helper is the per-format leg, selected by the caller, not a router: it "
    "is only reachable with a file of its own format, so the states that describe "
    "OTHER formats' failures cannot occur on it")

_row("lib_helper_image", {
    "clean": "clean",                          # an ordinary image, nothing hidden
    "finding": "threat",                       # instruction text in an EXIF field
    "incomplete_clean": "incomplete",          # OCR unavailable, nothing else found
    "incomplete_finding": "threat_incomplete", # OCR unavailable, EXIF still fires
    "unreadable": "operational", "missing": "operational",
    "missing_dependency": "incomplete",        # <- ASTRA F2: was complete/clean
    "truncated_finding": "threat_incomplete",
    "corrupt_parser_fail": "incomplete",       # PNG header, not a PNG
    "nonregular": "operational",
    "undecodable": _HELPER_WRONG_TYPE,
    "empty": "clean",                          # a valid blank image: decoded, no text
})

_row("lib_helper_pdf", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete", # <- ASTRA F4: the annotation fixture
    "unreadable": "operational", "missing": "operational",
    "missing_dependency": "incomplete",        # PyPDF2 absent
    "truncated_finding": "threat_incomplete",
    "corrupt_parser_fail": "incomplete",
    "nonregular": "operational",
    "undecodable": _HELPER_WRONG_TYPE,
    "empty": "clean",                          # a valid PDF with a blank page
})

_row("lib_helper_text", _file_surface({
    "missing_dependency": _HELPER_WRONG_TYPE,
    "corrupt_parser_fail": _HELPER_WRONG_TYPE,
    "incomplete_clean": _HELPER_WRONG_TYPE,
    "incomplete_finding": Alias(
        "truncated_finding",
        "this helper runs no extractor, so the size cap is its only way to lose "
        "coverage -- same input as `truncated + finding`"),
}))

# =========================================================================
# library -- the five public extractor convenience functions
#
# ASTRA: "distinct aggregates cannot inherit coverage by name." Before round 4
# each of these built its OWN per-source dictionary and dropped the child's
# truncation and extraction failures; they are now the same `result.aggregate()`
# call, so they get rows AND an equivalence assertion against the shared path.
# =========================================================================

_CONV_NO_ROUTER = NotApplicable(
    "a convenience function is the per-format leg its caller chose; it does no "
    "content sniffing and no routing, so states describing other formats cannot "
    "arise on it")

def _conv_row(name, extra=None):
    base = {
        "clean": "clean", "finding": "threat",
        "incomplete_clean": "incomplete",
        "incomplete_finding": "threat_incomplete",
        "unreadable": "operational", "missing": "operational",
        # The decoder's PACKAGE is absent (`_check_deps` raises). Distinct from
        # `incomplete_clean`, where the package imports and the decoder fails at
        # run time -- different mechanism, different warning, both incomplete.
        "missing_dependency": "incomplete",
        "truncated_finding": "threat_incomplete",
        "corrupt_parser_fail": "incomplete",
        "nonregular": "operational",
        "undecodable": _CONV_NO_ROUTER,
        # A valid input of this format with nothing in it: the decoder RAN and
        # produced nothing, which is a complete inspection of an empty document.
        # Contrast `corrupt_parser_fail`, where the decoder could not run at all.
        "empty": "clean",
    }
    base.update(extra or {})
    _row(name, base)

for _name in ("lib_conv_image", "lib_conv_pdf", "lib_conv_audio", "lib_conv_video"):
    _conv_row(_name)

# QR is the one convenience function with exactly ONE content source, and that
# changes which states can exist on it. Round 3 would have written these as N/A
# with the reason "not tested"; each of these is a claim about the surface.
_conv_row("lib_conv_qr", {
    "incomplete_clean": Alias(
        "missing_dependency",
        "a decoded symbol is this surface's only content source, so the only way "
        "to lose coverage on it is for the decoder to be unavailable -- the same "
        "input as `missing decoder`, asserted under that alias"),
    "incomplete_finding": NotApplicable(
        "this surface has exactly one content source. If QR decoding does not "
        "run there is no extracted text at all, so a finding and a coverage loss "
        "cannot coexist here -- unlike the image surface, which still has EXIF "
        "when OCR fails, and the PDF surface, which still has pages when an "
        "annotation fails"),
    "truncated_finding": NotApplicable(
        "the QR specification caps a symbol's payload at 2,953 bytes (version 40, "
        "level L, binary), three orders of magnitude below the engine's 1 MiB "
        "scan cap, so decoded QR text cannot reach truncation",
        claim="format"),
})

# =========================================================================
# the normalizer boundary
# =========================================================================

_NORMALIZE_NO_IO = NotApplicable(
    "`normalize()` takes an in-memory result object or mapping. It performs no I/O "
    "of any kind -- no path is resolved, no file opened, no bytes decoded, no "
    "parser run -- so every state defined by a filesystem or decoding failure "
    "reaches it only as a mapping that ALREADY records the failure, which is the "
    "`incomplete_*` cells")

_row("lib_normalize", {
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": "threat_incomplete",
    "unreadable": _NORMALIZE_NO_IO,
    "missing": _NORMALIZE_NO_IO,
    "missing_dependency": "incomplete",        # the dependency-warning dict shape
    "truncated_finding": "threat_incomplete",
    "corrupt_parser_fail": _NORMALIZE_NO_IO,
    "nonregular": _NORMALIZE_NO_IO,
    "undecodable": _NORMALIZE_NO_IO,
    "empty": "incomplete",                     # `{}` -- silence is not a pass
})
NOTES[("lib_normalize", "empty")] = (
    "INVERTED on purpose, and it is invariant 2. Everywhere else `empty` means "
    "'0 bytes of content, all of it read' -> clean. The analogous input HERE is a "
    "mapping that asserts nothing about coverage, and a document that never "
    "mentions `inspection_complete` did not prove an inspection. Silence is not a "
    "pass. The same test asserts the round-4 hardening: `normalize(None)` and "
    "`normalize(object())` raise TypeError rather than defaulting every axis to "
    "the optimistic value."
)

# =========================================================================
# MCP
# =========================================================================

_row("mcp_scan_text", _text_surface({
    "clean": "clean", "finding": "threat",
    "incomplete_clean": "incomplete",
    "truncated_finding": "threat_incomplete",
    "empty": "clean",
}))
NOTES[("mcp_scan_text", "empty")] = (
    "An empty STRING is content and gets the clean 0-bytes document, matching the "
    "CLI. A MISSING `text` argument is a different thing -- the tool's API contract "
    "was broken and nothing was submitted -- and stays `isError: true`; the test "
    "asserts both, because `if not text` used to collapse them into one error."
)

_row("mcp_scan_file_false", _file_surface())
_row("mcp_scan_file_true", _file_surface())

# The real transport. In-process handler tests cannot catch a framing, encoding or
# serialization bug between the handler and the client, and ASTRA's F3 (a FIFO
# stalling the server before it answered) was only visible over the wire.
_WIRE_EQUIV = NotApplicable(
    "the stdio leg exists to prove the TRANSPORT carries the document -- framing, "
    "Content-Length, JSON-RPC envelope, no stdout pollution. The verdict logic "
    "behind it is literally the same function object asserted in mcp_scan_file_*, "
    "and the four states below are the ones whose documents differ in SHAPE "
    "(error vs verdict, complete vs not), so they exercise every branch the "
    "transport has to carry")

_row("mcp_stdio", {
    "clean": _WIRE_EQUIV,
    "finding": "threat",
    "incomplete_clean": "incomplete",
    "incomplete_finding": _WIRE_EQUIV,
    "unreadable": "operational",
    "missing": _WIRE_EQUIV,
    "missing_dependency": _WIRE_EQUIV,
    "truncated_finding": _WIRE_EQUIV,
    "corrupt_parser_fail": _WIRE_EQUIV,
    "nonregular": "operational",
    "undecodable": _WIRE_EQUIV,
    "empty": _WIRE_EQUIV,
})


# =========================================================================
# accessors
# =========================================================================

def cells():
    """Every (surface, state) pair in declaration order."""
    for sid, group, label, formats in SURFACES:
        for state, _slabel, _sdesc in STATES:
            yield sid, group, label, formats, state, MATRIX[(sid, state)]


def is_na(value) -> bool:
    return isinstance(value, NotApplicable)


def is_alias(value) -> bool:
    return isinstance(value, Alias)


def outcome_of(value) -> str:
    """The outcome string a cell asserts, for a value that is not an alias."""
    if is_alias(value):  # pragma: no cover - callers use outcome_for()
        raise TypeError("an alias's outcome depends on the surface; use outcome_for()")
    return value


def outcome_for(surface, state) -> str:
    """The outcome this cell asserts, following an alias to its target's outcome.

    An alias names another STATE, not another outcome, so resolving it needs the
    surface: `lib_conv_qr/incomplete_clean` is driven as `missing_dependency`, and
    what it must produce is whatever THAT cell asserts on THIS surface.
    """
    value = MATRIX[(surface, state)]
    if is_alias(value):
        return MATRIX[(surface, value.state)]
    return value


def outcome_state(surface, state) -> str:
    """The state whose INPUT this cell is driven with.

    For an ordinary cell that is the state itself. For an ``Alias`` it is the
    alias target: the whole point of the label is that the two states are the
    same input on this surface, so the cell is executed with that input rather
    than declared away.
    """
    value = MATRIX[(surface, state)]
    if is_alias(value):
        return value.state
    return state


def coverage_counts():
    total = len(SURFACES) * len(STATES)
    na = sum(1 for *_x, value in cells() if is_na(value))
    alias = sum(1 for *_x, value in cells() if is_alias(value))
    return {"total": total, "asserted": total - na, "na": na, "alias": alias,
            "equivalences": len(EQUIVALENCE)}


# Every declared cell must exist; a missing key is a hole in the space.
_missing = [(s[0], st[0]) for s in SURFACES for st in STATES
            if (s[0], st[0]) not in MATRIX]
if _missing:  # pragma: no cover - import-time guard
    raise AssertionError(f"matrix has undeclared cells: {_missing}")

# An alias must point at a state this surface actually asserts, or it is a
# forward reference to nothing.
for _s in SURFACES:
    for _st in STATES:
        _v = MATRIX[(_s[0], _st[0])]
        if is_alias(_v):
            _target = MATRIX[(_s[0], _v.state)]
            if is_na(_target) or is_alias(_target):  # pragma: no cover
                raise AssertionError(
                    f"{_s[0]}/{_st[0]}: alias points at {_v.state!r}, which is "
                    f"not an asserted outcome on this surface")

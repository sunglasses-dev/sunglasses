"""Shapes for GLS-SD-010-EMB — the embedded assignment the parent cannot reach.

NOT ONE VALUE HERE HAS A RECOGNISABLE CREDENTIAL FORMAT, and that is the point
of the rule rather than a convenience of the fixture. `GLS-SD-001` already
catches an AWS key id, a Slack token or a PEM block wherever it sits, embedded
or not, so on a formatted value this rule's gap is invisible and a fixture built
from one would pass without the rule existing. The gap is only real for an
assignment whose value has no shape a scanner can recognise: a password, a DSN,
an internal token. Measured on `ec753bb` and recorded in
`warroom/SD010_ANCHOR_DIAGNOSIS_2026-09-21.md`.

It also keeps credential-shaped strings out of the repository, which is what we
tell everyone else to do, and what `sd_api_sibling_rows.py` was refused twice by
our own firewall for getting wrong.

THE AXIS IS THE BOUNDARY, not the key and not the prose. The parent's predicate
is `(?m)^KEY=`: an assignment at the start of a line, standing in for "this is a
config line, not a sentence". Every MUST_FIRE row below is that same assignment
with the line start replaced by some other real delimiter, and every BENIGN row
is something that looks like it from a distance and is not.
"""

# Assembled, not written: no literal in this file is a credential and none of
# them matches a real account.
PW = "hunter" + "2"
DSN = "postgres://svc:" + PW + "@db.internal:5432/app"
TOK = "z" + "9" * 6 + "q"


MUST_FIRE = {
    # ── the four embedded shapes from the diagnosis ──────────────────────
    "indented_two_spaces":
        "services:\n  app:\n    PASSWORD=" + PW + "\n",
    "indented_with_a_tab":
        "environment:\n\tPASSWORD=" + PW + "\n",
    "behind_a_quote_in_json":
        '{"cfg":"PASSWORD=' + PW + '"}',
    "escaped_newline_inside_a_json_string":
        '{"dump":"HOME=/root\\nPASSWORD=' + PW + '"}',

    # ── the shapes the review asked for by name ──────────────────────────
    "quoted_value_at_a_line_start":
        'PASSWORD="' + PW + '"\n',
    "assignment_behind_a_quote_dsn":
        '{"url":"DATABASE_URL=' + DSN + '"}',
    "indented_dsn_in_a_config_block":
        "defaults:\n    DATABASE_URL=" + DSN + "\n",
    "after_a_comma_in_a_serialised_list":
        "vars=[FOO=1,TOKEN=" + TOK + "]\n",

    # The parent's own shape. It must keep firing: a rule that widened the
    # anchor and lost the bare line start would read as coverage while having
    # traded one shape for another.
    "the_parent_shape_at_a_line_start":
        "PASSWORD=" + PW + "\n",
}


BENIGN = {
    # A BARE SPACE IS DELIBERATELY NOT A BOUNDARY. This single row is the whole
    # of what keeps the rule from blocking every page that names a variable.
    "prose_a_space_is_not_a_boundary":
        "Set your API_KEY= in the dashboard before you start the server.\n",

    # The case scope, stated as a fixture. The engine compiles every pattern
    # with re.IGNORECASE and offers no per-rule opt-out, so the key alternation
    # carries an inline `(?-i:...)`. Without it an indented lowercase keyword
    # argument in a constructor example is indistinguishable from an indented
    # config line, and both SDK READMEs in the corpus fire. Measured 2026-09-21:
    # 3 corpus docs case-folded, 1 case-sensitive.
    "lowercase_python_kwarg_indented":
        "client = Anthropic(\n    api_key=os.environ.get('ANTHROPIC_API_KEY'),\n)\n",
    "lowercase_kwarg_behind_a_quote":
        '{"call":"api_key=os.environ[\'K\']"}',

    # Variant C's disclosed cost, kept out: a backtick is not a boundary, so a
    # README documenting an env var inside a code span stays clean.
    "a_markdown_code_span":
        "Add `OPENAI_API_KEY=sk-x` to your `.env` file and restart.\n",

    # The name of a variable is public information; only its value is a secret.
    "the_key_name_with_no_assignment":
        "The PASSWORD variable is read once at boot and never logged.\n",
    "a_comparison_not_an_assignment":
        'if (TOKEN == expected) { grant(); }\n',
}


# ── RESEMBLANCE IS NOT EXACTNESS: the ${...} exclusion is WHOLE-VALUE ────────
#
# `${API_KEY}` as the entire value is a reference to a secret and is excluded.
# A value that merely BEGINS with a variable reference is a real secret with a
# variable prefix, and is not. A prefix test would have excluded both, which is
# the exact shape of the Sep-13 lesson: a rule that resembles the thing it is
# meant to recognise is not the same as one that matches it exactly.
#
# The values here are assembled and format-free for the same reason as
# everything else in this file: a credential-shaped literal would be caught by
# GLS-SD-001 and the fixture would pass without this rule existing.
MUST_FIRE["variable_prefix_then_a_real_value"] = (
    '{"cfg":"API_KEY=${PREFIX}' + "h0t" + "sauce9" + '"}')

# Bare `$IDENT` is deliberately NOT excluded this round: unbraced, it is
# ambiguous with a literal value that happens to start with a dollar. Pinned as
# an assertion so the narrower choice is the one that was made, not the one
# that happened.
MUST_FIRE["bare_dollar_identifier_still_fires"] = '{"cfg":"API_KEY=$FOO"}'


# Python's own repr. `str(dict)` and `repr()` emit single quotes, so a mapping
# that reaches a log line or a tool result normally looks like this rather than
# like JSON. The boundary class read `"` and not `'` until 2026-09-21 and this
# shape walked straight past it while its double-quoted twin blocked.
MUST_FIRE["single_quoted_python_dict"] = "{'cfg':'PASSWORD=" + PW + "'}"


# ── THE EVASIONS ASTRA FOUND, now must-fire rows ──────────────────────
#
# Round 1 of review refused the rule and raised both of these as analytical
# concerns. They reproduced. Every one of them returned `allow` against the
# shipped predicate at the time, and each is a real secret sitting in a real
# assignment.
#
# The first three are the TERMINATOR gap: the end-of-value test accepted `,`
# `}` `]`, which occur INSIDE a quoted value, so a `${VAR}` reference followed
# by one of them ended the "value" while the secret sat in the same string.
#
# The last three are the PREFIX gap, and they are the worse class: the
# placeholder tokens were matched as prefixes, so anyone able to influence the
# value prepended one to a strong secret and the rule went quiet. A detection
# rule whose suppression an attacker can trigger is worse than one with a
# documented false positive. That is why the prose tokens are gone entirely
# rather than tightened.
_S = "hunter" + "2" + "x9q"
MUST_FIRE["evasion_brace_ref_then_comma_then_secret"] = '{"cfg":"API_KEY=${VAR},' + _S + '"}'
MUST_FIRE["evasion_brace_ref_then_brace_then_secret"] = '{"cfg":"API_KEY=${VAR}}' + _S + '"}'
MUST_FIRE["evasion_brace_ref_then_bracket_then_secret"] = '{"cfg":"API_KEY=${VAR}]' + _S + '"}'
MUST_FIRE["evasion_example_prefix_on_a_strong_value"] = '{"cfg":"PASSWORD=example' + _S + '"}'
MUST_FIRE["evasion_your_prefix_on_a_strong_value"] = '{"cfg":"PASSWORD=your_' + _S + '"}'
MUST_FIRE["evasion_xxx_prefix_on_a_strong_value"] = '{"cfg":"PASSWORD=xxx' + _S + '"}'

# These two were DISCLOSED COSTS of the prose tokens. The prose tokens are gone,
# so they are costs no longer and they belong on the other side of the ledger.
# Keeping them here, as must-fire, is what stops the tokens coming back quietly.
MUST_FIRE["a_placeholder_shaped_but_real_password"] = '{"cfg":"PASSWORD=example123"}'
MUST_FIRE["a_redacted_looking_but_real_value"] = "config:\n    PASSWORD=xxxxxxxx\n"


# ── what the rule still does not report ────────────────────────────
#
# ONE row, not three. A `${VAR}` interpolation is a REFERENCE to a secret: the
# value is absent by construction, there is nothing in the text to leak. It must
# be the ENTIRE value and the value must then end, so a secret cannot ride along
# behind it -- the three evasion rows above are what enforces that.
DISCLOSED_MISSES = {
    "a_compose_interpolation":
        'services:\n  app:\n    environment:\n      - "API_KEY=${API_KEY}"\n',
}


# The two shapes above that sit at a real line start, so GLS-SD-010 reaches
# them too. On the channels the parent declares, severity-ranked dedup reports
# the PARENT and suppresses this rule's id -- the same shadowing
# `sd_api_sibling_rows.py` documents for the -API siblings. They are kept in
# MUST_FIRE because a widened anchor that LOST the bare line start would have
# traded one shape for another while still reading as coverage; the test proves
# this rule covers them by removing the parent and watching it name itself.
PARENT_ALSO_COVERS = {
    "the_parent_shape_at_a_line_start",
    "quoted_value_at_a_line_start",
}

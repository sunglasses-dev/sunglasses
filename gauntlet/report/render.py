"""Turn a validated artifact into a page, and refuse to turn an invalid one.

Three rules decide everything here.

NO NUMBER IS TYPED BY A HUMAN. Every figure is rendered from the artifact and
carries `data-bound` naming the field it came from, so a gate can check the page
against the JSON without trusting either. This is the defect that told visitors
924 for months when the answer was 962, and told the demo 1,540 while it served
1,437.

A STATE IS NOT A NUMBER. A panel that is not `measured` or `historical` renders
its state word and its reason, never a digit. `not_computed` is not zero and
`unavailable` is not false. The sentence beside it is SELECTED BY the state from
a template below, never authored next to it, because an author's sentence goes
stale silently while the boolean it explains flips (N1/N2).

THE BASE PAGE CLAIMS NOTHING CURRENT. E6: a build-time freshness warning cannot
change after the publisher stops, so the HTML that arrives with no script, or
with a broken one, already says current freshness is unverified and shows no
green. The script can only ever REMOVE that caveat, never add one, so every
failure mode of the script lands on the honest side.
"""
from __future__ import annotations

import html as html_mod
import json

import schema
import validate

# One sentence per state. Selected, never authored beside the value.
CEILING_TEMPLATES = {
    "not_computed": (
        "Not computed. {unclassified_count} operations have no reviewed "
        "capability classification, so this run refused to publish a ceiling "
        "rather than guess one. The unresolved operations are listed below."),
    "not_applicable": (
        "Does not arise. No variant is blocked, so there is nothing for a "
        "ceiling to describe."),
    "true": (
        "Under the pinned inputs recorded above, adapter-only work cannot "
        "unlock the remaining schedules: every one of the "
        "{blocked_needing_route} blocked variants names at least one real-route "
        "capability. A later change names the route, adapter or corpus change "
        "that moved it."),
    "false": (
        "{blocked_by_adapter_work_alone} of the blocked variants need no "
        "real-route capability, so this is not a ceiling. That is a statement "
        "about where the remaining work sits, not a product failure."),
}

STATE_WORDS = {
    "measured": "measured this run",
    "historical": "a dated earlier examination",
    "not_computed": "not computed",
    "not_applicable": "does not arise",
    "unavailable": "unavailable",
    "invalid": "invalid",
    "not_run": "not run",
}


class WillNotRender(Exception):
    """The artifact did not validate. A page is not built from one that did not."""


def _esc(value) -> str:
    return html_mod.escape(str(value), quote=True)


def _figure(path: str, value) -> str:
    """A number that cites the field it came from."""
    return f'<span class="fig" data-bound="{_esc(path)}">{_esc(value)}</span>'


def _state_note(panel: dict) -> str:
    state = panel.get("state")
    code = panel.get("reason_code")
    detail = panel.get("detail") or schema.REASON_CODES.get(code, "")
    word = STATE_WORDS.get(state, state)
    body = f'<p class="state state-{_esc(state)}">{_esc(word)}'
    if code:
        body += f' <code>{_esc(code)}</code>'
    body += "</p>"
    if detail:
        body += f'<p class="detail">{_esc(detail)}</p>'
    return body


def _coverage_section(report: dict) -> str:
    coverage = report["coverage"]
    if not schema.numeric_readable(coverage):
        return ('<section id="coverage"><h2>What the harness can drive</h2>'
                + _state_note(coverage) + "</section>")

    plan = coverage["plan_partition"]
    parts = [
        '<section id="coverage"><h2>What the harness can drive</h2>',
        "<p>",
        _figure("coverage.plan_partition.drivable", plan["drivable"]),
        " of ",
        _figure("coverage.total", coverage["total"]),
        " delivered schedules are drivable by this adapter against the pinned "
        "corpus recorded above. Further coverage requires real-route "
        "capabilities; expanding the stand-in is excluded by the adopted plan.",
        "</p>",
        '<p class="detail">Planning and execution are separate counts. '
        "Being drivable is not being run, and being run is not passing. ",
        "Executed this run: ",
        _figure("coverage.execution_partition.passed",
                coverage["execution_partition"]["passed"]),
        " passed, ",
        _figure("coverage.execution_partition.not_run",
                coverage["execution_partition"]["not_run"]),
        " not run.</p>",
    ]

    ceiling = coverage["ceiling"]
    state = ceiling["state"]
    template = CEILING_TEMPLATES.get(state, "")
    try:
        sentence = template.format(**{k: v for k, v in ceiling.items()
                                      if isinstance(v, (int, str))})
    except (KeyError, IndexError):
        sentence = ""
    parts.append('<h3>Could adapter work alone unlock the rest</h3>')
    parts.append(f'<p class="state state-{_esc(state)}">{_esc(sentence)}</p>')

    if state == "not_computed":
        parts.append("<ul class='unresolved'>")
        for op, reason in sorted((ceiling.get("unclassified") or {}).items()):
            parts.append(f"<li><code>{_esc(op)}</code> {_esc(reason)}</li>")
        parts.append("</ul>")
    parts.append("</section>")
    return "".join(parts)


def _routes_section(report: dict) -> str:
    parts = ['<section id="routes"><h2>What the product route satisfied</h2>']
    for index, route in enumerate(report.get("routes") or []):
        kind = route.get("implementation_kind")
        parts.append(f'<h3>{_esc(route.get("name"))}</h3>')
        parts.append(f'<p class="detail">Implementation kind: '
                     f'<code>{_esc(kind)}</code>. ')
        if kind == "harness_stand_in":
            parts.append("A stand-in is an instrument, not the product. Its "
                         "planning counts are never route conformance.")
        parts.append("</p>")
        head = route.get("head")
        parts.append('<p class="detail">Measured at head: '
                     + (_figure(f"routes[{index}].head", head) if head
                        else "<em>not bound</em>")
                     + f'. Origin reachability: <code>'
                     f'{_esc(route.get("head_reachable_on_origin"))}</code>.</p>')
        parts.append(_state_note(route.get("rows") or {}))
    parts.append("</section>")
    return "".join(parts)


def render(report: dict, *, findings: list | None = None) -> str:
    """The page, or a refusal to build one."""
    findings = validate.validate_report(report) if findings is None else findings
    if findings:
        raise WillNotRender(
            f"{len(findings)} validation finding(s); the first is {findings[0]}")

    run, fresh = report["run"], report["freshness"]
    embedded = json.dumps({
        "measured_at": fresh.get("measured_at"),
        "policy_hours": fresh.get("policy_hours"),
        "outcome": run.get("outcome"),
    })

    return f"""<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nightly gauntlet</title>
<style>
 :root {{ color-scheme: dark; }}
 body {{ background:#0a0a0a; color:#e8e8e8; margin:0;
        font:16px/1.65 ui-sans-serif,system-ui,-apple-system,sans-serif; }}
 main {{ max-width:56rem; margin:0 auto; padding:2rem 1rem 4rem; }}
 h1,h2,h3 {{ color:#00ccff; line-height:1.25; }}
 h1 {{ font-size:1.7rem; }} h2 {{ font-size:1.25rem; margin-top:2.5rem; }}
 h3 {{ font-size:1rem; margin-top:1.75rem; }}
 code {{ background:#151515; padding:.1em .35em; border-radius:3px;
        font-size:.87em; word-break:break-all; }}
 .fig {{ font-variant-numeric:tabular-nums; font-weight:600; color:#fff; }}
 .detail {{ color:#9aa0a6; font-size:.92rem; }}
 .state {{ margin:.4rem 0; }}
 .state-unavailable, .state-not_computed, .state-invalid {{ color:#ffc857; }}
 .state-measured, .state-historical {{ color:#8fe388; }}
 .unresolved li {{ color:#9aa0a6; margin:.3rem 0; }}
 #freshness {{ border:1px solid #333; border-left:3px solid #ffc857;
              padding:.75rem 1rem; margin:1.5rem 0; }}
 @media (max-width:375px) {{ main {{ padding:1.25rem .75rem 3rem; }} }}
</style>
<main>
<h1>What our own adversarial harness proved last night</h1>
<p class="detail">This page is an organization-run test of our own work, with
observations recorded outside the process under test. It is not a third party
certification. It publishes where the harness proves nothing as plainly as where
it proves something, because a dashboard that only shows its good days is
indistinguishable from one that is broken.</p>

<div id="freshness">
 <p id="freshness-note">Current freshness is <strong>unverified</strong> in this
 copy of the page. Nothing here is a claim about the present until the age of
 the measurement below has been checked against your own clock.</p>
 <p class="detail">Measured at
 {_figure("freshness.measured_at", fresh.get("measured_at"))},
 under a policy of {_figure("freshness.policy_hours", fresh.get("policy_hours"))}
 hours. Age is checked against the reader's clock, which is not a server time
 attestation.</p>
</div>

<section id="run">
<h2>The run itself</h2>
<p>Run {_figure("run.id", run["id"])}, attempt
{_figure("run.attempt", run["attempt"])}, finished
{_figure("run.finished_at", run["finished_at"])}, outcome
{_figure("run.outcome", run["outcome"])}, exit code
{_figure("run.exit_code", run["exit_code"])}.</p>
<p class="detail">A run that refuses still publishes this report and still exits
nonzero. Those are not in tension: if a refusing run published nothing, the last
good page would stay up and a broken harness would look exactly like a passing
one from out here.</p>
</section>

<section id="harness">
<h2>Whether the instrument met its examined requirements</h2>
{_state_note(report["harness"])}
<p class="detail">This is a finding an examiner makes about the instrument on a
dated head under a named contract. A nightly run cannot make it about itself
from its own passing suite.</p>
</section>

{_coverage_section(report)}
{_routes_section(report)}

<section id="method">
<h2>Method accounting</h2>
{_state_note(report["ledger"])}
<p class="detail">Counted in charged driver invocations, which are not dollars
and not provider requests. A deterministic run adds none.</p>
</section>

<section id="inputs">
<h2>What this was measured against</h2>
<p class="detail">Corpus digest
{_figure("identities.corpus_digest", report["identities"]["corpus_digest"])}.
Capability map revision
{_figure("identities.capability_map_revision",
         report["identities"]["capability_map_revision"])}, review state
{_figure("identities.capability_map_review_state",
         report["identities"]["capability_map_review_state"])}.</p>
</section>
</main>
<script>
(function () {{
  // The ONLY thing this script may do is remove the caveat, and only while the
  // measurement is genuinely inside its policy window. Every way it can fail,
  // including not running at all, leaves the honest text in place.
  var d = {embedded};
  var note = document.getElementById("freshness-note");
  function check() {{
    var t = Date.parse(d.measured_at);
    if (!t || !d.policy_hours) return;
    var ageHours = (Date.now() - t) / 3600000;
    if (ageHours < 0) return;                 // a future measurement is invalid
    if (ageHours > d.policy_hours) {{
      note.innerHTML = "This measurement is <strong>stale</strong> by the " +
        "published policy. It is a dated historical record, not a current " +
        "statement.";
      return;
    }}
    if (d.outcome !== "complete") return;     // a refusal never earns a green
    note.textContent = "Measured within the published freshness window, " +
      "checked against your own clock.";
  }}
  check();
  setInterval(check, 60000);                  // a tab left open goes stale too
}})();
</script>
"""

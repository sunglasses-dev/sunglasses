# Claude Code integration — the firewall hook, end to end

Every command and output on this page was run against the **public
`sunglasses==0.5.6` wheel** from PyPI (746,645 bytes, sha256
`4385c70bc1edabaaa38089fc14e83ae7917e17b9351c6813887589a195d20999`), installed
cold into a fresh virtualenv, in a **throwaway project directory**. Nothing is
paraphrased from memory.

## What this integration actually is

`sunglasses scan` is something you invoke. The firewall hook is different: Claude
Code calls it **before every tool use**, hands it the pending call as JSON on
stdin, and honours the decision it prints. That is what lets it stop an action
rather than describe one after the fact.

Two limits, up front:

- **It is best-effort under load.** The hook is registered with a 10-second
  timeout. A hook that times out does **not** block the call. See
  `KNOWN_VERSION_GAPS.md`.
- **It is deterministic-only.** It blocks secret material leaving in an outbound
  call, plus rules you write in `~/.sunglasses/policy.yaml`. Pattern and intent
  matches **escalate to you** — they never auto-deny. That is a deliberate choice:
  a heuristic that silently kills tool calls gets uninstalled by lunchtime.

## Install it — in a disposable project first

```bash
python3 -m venv .venv && ./.venv/bin/pip install sunglasses
cd /path/to/a/throwaway/project
./.venv/bin/sunglasses init
```

> **`init` writes to `./.claude/settings.json` by default — project-local.**
> `--global` writes to `~/.claude/settings.json` instead. Try it project-local
> first: a global install means the very next tool call in every session goes
> through a build you have not exercised yet.

Real output:

```
  SUNGLASSES — self-testing the hook command...
  Self-test passed (hook answered 'defer')
  Firewall installed -> /path/to/project/.claude/settings.json
  /path/to/.venv/bin/python3.14 -m sunglasses.firewall

  Your /Users/you/.sunglasses/policy.yaml is untouched.

  What it blocks (deterministic facts only)
    - secret material leaving in an outbound tool call
    - rules you write in ~/.sunglasses/policy.yaml
  What it never blocks
    - pattern/intent matches. Those escalate to you, never auto-deny.
```

Note the **self-test before the write**: it runs the hook command once and
requires an answer before registering it, so a broken interpreter path fails at
install time instead of on your next tool call.

What lands in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/.venv/bin/python3.14 -m sunglasses.firewall",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

The command is an **absolute interpreter path**, so the hook keeps working when
Claude Code runs with a different `PATH`.

## What it does, on four real calls

The hook reads the pending call on stdin and prints its decision on stdout. These
are verbatim runs against the public wheel.

**1. An ordinary call proceeds.**

```
$ echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | python -m sunglasses.firewall
{}
exit 0
```

Empty object = no opinion; Claude Code proceeds.

**2. A secret leaving in an outbound call is stopped.**

```
$ python -m sunglasses.firewall < outbound-token.json
{"hookSpecificOutput": {"hookEventName": "PreToolUse",
 "permissionDecision": "deny",
 "permissionDecisionReason": "SUNGLASSES firewall: blocked — GitHub token material
 detected in an outbound Bash call. Fingerprint sha256:620e24b63197 (material
 withheld). Pass credentials by environment variable or secret manager instead.
 If this key is a published test fixture, add it to KNOWN_PUBLIC_CANARIES."}
}
exit 0
```

The event was a `curl -X POST … -d token=<GitHub token>`. Two details worth
noticing: the **material is withheld** from the reason string and identified by a
truncated fingerprint, so your secret does not get copied into a transcript by the
thing protecting it — and the reason tells you what to do instead, including the
escape hatch if the value is a published test fixture.

**3. The same secret, not leaving, proceeds.** *(the control that makes case 2 mean something)*

```
$ python -m sunglasses.firewall < local-token.json     # echo <same token> > local.txt
{}
exit 0
```

Identical secret, identical tool, different destination. The rule is about
**egress**, not about the presence of a credential — otherwise it would fire on
every line of code that mentions a key and you would turn it off.

**4. A file read proceeds.**

```
$ echo '{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}' | python -m sunglasses.firewall
{}
exit 0
```

Note the exit code is `0` in all four cases, including the deny. The hook
communicates through the JSON contract, not through process status.

## The audit trail

```bash
sunglasses receipts --limit 5
```

```
  20:18:04  defer  deterministic Bash    GLS-FW-CLEAN
  20:18:04  deny   deterministic Bash    GLS-FW-SEC-GITHUB
  20:18:04  defer  deterministic Bash    GLS-FW-CLEAN
  20:18:04  defer  deterministic Read    GLS-FW-CLEAN
```

**Every call is recorded, not just the blocks.** `defer` means checked, nothing
provable found. That distinction is the point: a log containing only denials
cannot tell you whether the hook was running at all during the window you care
about. A totals line and a rule ID accompany each row.

## Removing it

```bash
sunglasses init --uninstall
```

```
  Firewall hook removed from /path/to/project/.claude/settings.json
  Your other hooks were left untouched. A timestamped backup sits next to the file.
```

Verified: `.claude/settings.json` is left as `{}` — the file and any other hooks in
it survive, only our entry is removed, and a timestamped backup is written first.

## What this does **not** cover

Say the limits plainly, because an integration people over-trust is worse than
none:

- **A timed-out hook does not block.** 10-second budget; under load the call
  proceeds. Documented in `KNOWN_VERSION_GAPS.md`.
- **It does not read tool *results*.** This is `PreToolUse`. Content that arrives
  as the *output* of a tool call is not inspected here — pipe it through
  `sunglasses scan` if you need that.
- **Pattern and intent matches do not auto-deny.** They escalate. If you want a
  hard block on something specific, write it in `~/.sunglasses/policy.yaml`.
- **Secret detection is pattern-based**, so a credential in a format we do not
  recognise will not be caught. It is a floor, not a guarantee.
- **It protects the agent's *actions*, not your agent's reasoning.** Nothing here
  prevents a model from being persuaded — only from executing a specific class of
  call.

## Reproducing this page

```bash
python3 -m venv /tmp/sg && /tmp/sg/bin/pip install "sunglasses==0.5.6"
mkdir /tmp/demo && cd /tmp/demo && /tmp/sg/bin/sunglasses init
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | /tmp/sg/bin/python -m sunglasses.firewall
/tmp/sg/bin/sunglasses receipts --limit 5
/tmp/sg/bin/sunglasses init --uninstall
```

If any output on this page does not match what you get, that is a bug worth an
issue — the page is meant to be checkable, not decorative.

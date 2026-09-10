# Security Policy

Sunglasses inspects content before an AI agent acts on it. The failure mode that
matters most here is not a crash — it is a **quiet wrong answer**: content that
should have been flagged and was not, or a file reported as clean that nobody
actually read. If you have found one of those, we want to hear about it, and
reporting it is a contribution rather than an attack on the project.

## Reporting a vulnerability

**Please do not open a public issue for a working exploit.**

| channel | use it for |
|---|---|
| [**Report a vulnerability**](https://github.com/sunglasses-dev/sunglasses/security/advisories/new) (Security tab) | anything exploitable — private, coordinated disclosure built in. **Preferred.** |
| `security@sunglasses.dev` | same, if you would rather use email |
| [Bypass or false positive issue](https://github.com/sunglasses-dev/sunglasses/issues/new?template=bypass_report.yml) | a detection gap with no live exploit attached — public is fine and helps other users |

Private reporting through the Security tab is **enabled** on this repository; you
do not need to be a maintainer to open a report.

### What to include

The four things that let us reproduce without interviewing you:

1. **The exact input** — the file or string, as close to verbatim as you can
   share. Redact real secrets; a minimal synthetic reproducer is ideal.
2. **The exact command** — e.g. `sunglasses scan --file notes.pdf`.
3. **Expected versus observed exit code.** `0` clean · `1` threat found ·
   `2` usage/operational error · `3` incomplete inspection.
4. **Version and environment** — `sunglasses --version` and `sunglasses check`
   (the second matters: a missing native decoder changes what can be read at all).

## What we commit to

- **Acknowledgement within 3 business days.** This project is maintained by a
  very small team. If you have not heard back in that window, the report did not
  reach us — please chase it on the other channel rather than assuming it was
  ignored.
- **An initial assessment and severity within 7 days** of acknowledgement.
- **Coordinated disclosure.** We agree a timeline with you before any public
  detail. If a fix is going to take longer than the window we agreed, we tell you
  rather than letting it lapse quietly.
- **Credit in the release notes**, unless you would rather stay anonymous.

We would rather publish a smaller promise we keep than a faster one we miss.

## Scope

**In scope:**

- **Detection bypass** — content carrying an attack this project claims to catch,
  that produces no finding. Including obfuscation, encoding and carrier tricks.
- **False-clean / coverage misreporting** — anything that reports a complete
  inspection when part of the input was not actually read, or returns `0` where
  `3` is the truth. This is the class v0.5.6 exists to repair, and we take it as
  seriously as a missed pattern.
- **False-positive classes** — a rule that fires broadly on ordinary content.
  Trust lost to false positives is trust lost either way.
- **Anything in the scanner, CLI, MCP server or Claude Code hook** that affects a
  trust decision — including the hook failing open in a way the documentation does
  not describe.

**Out of scope:**

- Vulnerabilities in your own agent, or in third-party services whose content you
  are scanning. We are still happy to help you interpret a finding.
- A single crafted string that defeats one pattern where the documented behaviour
  is best-effort matching. Report it as a bypass issue — it is useful, it is just
  not an emergency.
- Anything already listed in `KNOWN_VERSION_GAPS.md`. Those are published limits,
  not surprises. If you can show one is *worse* than documented, that is in scope.

## Supported versions

The latest version published on PyPI receives security fixes. Older versions are
not patched — `pip install -U sunglasses`.

## Advisory history

**No security advisories have been published for this project to date.**

The closest thing is [v0.5.6](https://github.com/sunglasses-dev/sunglasses/releases/tag/v0.5.6),
which repaired a false-clean class: six paths returned a success-shaped answer for
content nobody had read — a directory passed as a file, a non-existent path scanned
as prose, an archive's compressed bytes scanned as text, input past the size cap,
audio without `--deep`, and a deep scan whose transcription failed where the ffmpeg
error message was scanned *as if it were the transcript*. `is_clean` also changed
meaning: it now requires a complete inspection as well as no findings.

**If you are on 0.5.5 or earlier, upgrade.** That release was found in our own
review rather than reported by an outside researcher, which is why there is no
advisory attached to it — not because it did not matter.

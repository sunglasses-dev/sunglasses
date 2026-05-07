# Known Version Gaps — Sunglasses

This document acknowledges historical gaps in the Sunglasses release sequence on PyPI and in git tags. It exists so anyone auditing the project (security researcher, contributor, downstream user) sees a transparent record of what's missing and why.

**Going forward (post May 6, 2026):** preflight CHECK 17 (`preflight-version-chain.sh`) blocks any new ship that would skip a patch number, and a daily integrity check (`sunglasses-integrity-check.sh`) runs at 6 AM PT to surface any new drift.

## PyPI gaps (allowlisted)

These versions never made it to PyPI. They are intentionally NOT being uploaded retroactively, because:
1. `pip install sunglasses` works correctly — pulls latest, no impact on users
2. `pip install sunglasses==X` works for any X that exists
3. Retroactive uploads with stale code would create more confusion than they resolve

- pypi-gap: 0.2.1 — pre-launch experimental, never published
- pypi-gap: 0.2.2 — pre-launch experimental, never published
- pypi-gap: 0.2.3 — pre-launch experimental, never published
- pypi-gap: 0.2.4 — pre-launch experimental, never published
- pypi-gap: 0.2.7 — pre-launch experimental, never published
- pypi-gap: 0.2.8 — pre-launch experimental, never published
- pypi-gap: 0.2.9 — pre-launch experimental, never published
- pypi-gap: 0.2.27 — daily-push cron silently failed twine upload (post-launch); patterns shipped to git, never reached PyPI
- pypi-gap: 0.2.30 — same root cause as 0.2.27; daily-push cron upload silently failed

## Tag gaps (recovered May 6, 2026)

These tags were missing from git when the integrity audit ran on May 6, 2026. They were created retroactively pointing at the commit where each version's `__init__.py` was bumped, and pushed to origin.

Recovered: v0.2.16, v0.2.18, v0.2.22, v0.2.27, v0.2.28, v0.2.30, v0.2.31, v0.2.32, v0.2.33.

## Pre-launch tags (allowlisted — no recovery)

These very early PyPI versions never had matching git tags and the original commits are too tangled to find clean source for. Allowlisted because they're irrelevant to current users and recovering them adds no value.

- tag-gap: 0.1.0
- tag-gap: 0.1.1
- tag-gap: 0.2.0
- tag-gap: 0.2.5
- tag-gap: 0.2.6

## How to add a new gap to this allowlist

If a future PyPI gap is unavoidable (e.g. version yanked due to security issue):
- Add `- pypi-gap: 0.X.Y — <reason>` to the section above
- Re-run `bash ~/.claude/tools/sunglasses-integrity-check.sh` to confirm allowlist takes effect

The integrity check reads this file and only flags NEW unallowlisted gaps. Allowlisted entries pass silently.

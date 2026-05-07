# Known Version Gaps

Quick FYI: an audit on May 6, 2026 surfaced some historical gaps in this project's version history. We fixed what was fixable and documented the rest.

## What we found

- 9 PyPI versions were never published (7 pre-launch + `0.2.27` and `0.2.30` which failed silent uploads)
- 8 git tags were missing for shipped versions

## What we did

- **Tags:** all 8 missing tags were created retroactively pointing at the right commits, then pushed.
- **PyPI gaps:** left as-is. `pip install sunglasses` works fine; retroactive uploads with stale code would create more confusion than they resolve.

## Going forward

- Pre-flight gate blocks any new ship that would skip a patch number.
- Daily 6 AM PT integrity check audits PyPI ↔ git tags ↔ CHANGELOG ↔ live site and surfaces drift before it builds up.

## Allowlist (machine-readable — integrity check parses these)

PyPI versions accepted as not-published:
- pypi-gap: 0.2.1
- pypi-gap: 0.2.2
- pypi-gap: 0.2.3
- pypi-gap: 0.2.4
- pypi-gap: 0.2.7
- pypi-gap: 0.2.8
- pypi-gap: 0.2.9
- pypi-gap: 0.2.27
- pypi-gap: 0.2.30

Pre-launch tags accepted as not-recovered:
- tag-gap: 0.1.0
- tag-gap: 0.1.1
- tag-gap: 0.2.0
- tag-gap: 0.2.5
- tag-gap: 0.2.6

To allowlist a future gap, add a `- pypi-gap: X.Y.Z` or `- tag-gap: X.Y.Z` line above and re-run the integrity check.

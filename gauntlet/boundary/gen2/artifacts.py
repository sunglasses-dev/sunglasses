"""The artifacts the adapter drives, read from ASTRA's delivery and never rebuilt.

T9's call, 2026-09-13 12:19. The 74 materialised directories ASTRA delivered are
the artifacts of record. `delivery_validation.json` counts 1,158 artifact hashes
over them, and `profile_steps` inside each schedule is a contract he froze.

THE MATERIALISER BESIDE THEM IS STALE and must not be used to regenerate these.
It is an older build than the run that produced this delivery: a fresh build of
G2-13.error_message drops `profile_steps` entirely, drops `limits_status`, loses
the `execute_profile` step's back reference, and never writes the
`pending-clean.response.jsonl` that the delivered copy carries. Thirteen of the
fifteen shared files come out byte identical; the two that differ are
`materialization.json`, which merely records the path, and the schedule, which
is the thing the adapter executes. Regenerating would replace a frozen contract
with a lesser one and nothing above here could tell. When ASTRA sends the newer
materialiser it gets run into a fresh output root and diffed against these 74
first; only then does the source change.

Read only. Nothing in this module writes into the review directory.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import sys

MATERIALISED = (pathlib.Path.home() / "Desktop" / "SUNGLASSES_ASTRA_REVIEW_2026-09-04"
                / "GATE3_DESIGN_REVIEW_2026-09-13" / "materialized")

# `materialization.json` is written last and so cannot list itself. Everything
# else in the directory has to appear in it.
SELF = "materialization.json"


class ArtifactsNotAsDelivered(Exception):
    """A delivered directory is not what its own record says it is."""


@dataclasses.dataclass(frozen=True)
class Record:
    """One variant's delivered artifacts. Paths in, bytes and data out."""
    path: pathlib.Path
    schedule: dict
    payload: bytes
    digest: str
    artifacts: dict[str, str]


def of_record(entry: dict, variant: dict, *,
              materialised: pathlib.Path | None = None) -> Record:
    """The delivered artifacts for one variant, verified against their own record.

    Three separate questions, because two of them cannot answer the third:
      every listed artifact still hashes to what was recorded
      nothing is in the directory that the record does not list
      the stimulus the artifacts were built from is the one the seed names

    The second is the one a hash sweep alone misses. Every listed file can match
    while the directory holds one more than ASTRA recorded, and anything that
    reads the directory rather than the list would pick it up.
    """
    root = (MATERIALISED if materialised is None else pathlib.Path(materialised))
    path = root / f"{entry['id']}.{variant['name']}"
    where = f"{entry['id']}.{variant['name']}"

    try:
        record = json.loads((path / SELF).read_text())
    except OSError as exc:
        raise ArtifactsNotAsDelivered(
            f"{where}: no delivered artifacts at {path} ({exc})") from exc

    listed = {a["path"]: a["sha256"] for a in record["artifacts"]}
    on_disk = {str(f.relative_to(path)) for f in path.rglob("*") if f.is_file()}

    unlisted = sorted(on_disk - set(listed) - {SELF})
    if unlisted:
        raise ArtifactsNotAsDelivered(
            f"{where}: {unlisted} are in {path} and not in its own record. "
            "Every listed artifact may still match; a directory holding more "
            "than was delivered is a different fixture.")

    absent = sorted(set(listed) - on_disk)
    if absent:
        raise ArtifactsNotAsDelivered(
            f"{where}: {absent} are recorded and not on disk at {path}")

    moved = [name for name, sha in sorted(listed.items())
             if hashlib.sha256((path / name).read_bytes()).hexdigest() != sha]
    if moved:
        raise ArtifactsNotAsDelivered(
            f"{where}: {moved} no longer hash to what was delivered. The grid "
            "would run on an edited fixture and report the difference as a "
            "candidate defect.")

    ref = variant.get("payload_ref") or {}
    source = record.get("payload_source") or {}
    if source.get("sha256") != ref.get("sha256"):
        raise ArtifactsNotAsDelivered(
            f"{where}: the artifacts were built from a payload hashing "
            f"{source.get('sha256')} and the seed names {ref.get('sha256')}. "
            "The artifacts carry one stimulus and every expectation was written "
            "against another.")

    schedule = json.loads((path / variant["schedule_file"]).read_text())
    return Record(path=path, schedule=schedule, payload=_payload(variant),
                  digest=_digest(listed), artifacts=listed)


def _digest(listed: dict[str, str]) -> str:
    """One value for the receipt, over the whole delivered set."""
    return hashlib.sha256(
        "\n".join(f"{name} {listed[name]}" for name in sorted(listed)).encode()
    ).hexdigest()


def _payload(variant: dict) -> bytes:
    """One resolver, T8's, in `runner`."""
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    import runner
    return runner.resolve_payload_ref(variant)

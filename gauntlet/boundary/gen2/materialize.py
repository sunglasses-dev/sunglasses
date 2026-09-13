"""Materialising a second generation variant, and the two copies underneath it.

The sixteen new seeds cannot materialise as delivered. Each `run.py` executes
`parents[2]/materialize_specs.py`, which resolves to the warroom root, and the
materialiser is not there. It lives in ASTRA's review directory, and it builds
from its OWN `fixtures/` copy of the seeds rather than from the installed
package.

So every new seed exists twice: the loader reads the package copy and the
materialiser reads the review copy. They are byte identical today. The check
below is for the day they are not, because a run would then report on a
scenario the harness never read, and at every layer above it that is
indistinguishable from a candidate defect.

Nothing here writes into the package. The check reads both copies and refuses.
"""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import pathlib
import subprocess
import sys

PACKAGE = pathlib.Path.home() / ".claude" / "state" / "warroom" / "GATE2_SCENARIOS"
REVIEW_ROOT = (pathlib.Path.home() / "Desktop" / "SUNGLASSES_ASTRA_REVIEW_2026-09-04"
               / "GATE3_DESIGN_REVIEW_2026-09-13")
REVIEW = REVIEW_ROOT / "fixtures"
MATERIALISER = REVIEW_ROOT / "materialize_specs.py"

# ASTRA's script refuses a root anywhere else, and it is right to: these runs
# create pipes, children and a file observer, and a fixture root that could
# resolve into a real tree is a fixture that can reach one.
PRIVATE_TMP = pathlib.Path("/private/tmp")


class UnsafeRunRoot(Exception):
    """A run root outside the private temporary tree."""


class SeedCopiesDiverged(Exception):
    """The package copy and the materialiser's copy of a seed disagree."""


class MaterialisationFailed(Exception):
    """The materialiser did not produce what the variant names."""


@dataclasses.dataclass(frozen=True)
class Built:
    """What a materialised variant hands the adapter. Bytes, never paths back."""
    run_root: pathlib.Path
    schedule: dict
    payload: bytes
    seed_digest: str


def _tree(directory: pathlib.Path) -> dict[str, str] | None:
    """Every file in the seed directory, by name and digest.

    The whole directory and not just scenario.json. The schedule's
    `assert_five_layers` step points at the REVIEW copy's expected.json while
    the harness grades against the package's, so two expectations that disagree
    produce a verdict about a contract nobody wrote.

    Scoped to the seed directories on purpose. The package root also carries
    PROVENANCE.md and SHA256SUMS that T8 regenerates, and hashing the root would
    report those as drift when they are the opposite of drift.
    """
    if not directory.is_dir():
        return None
    return {str(f.relative_to(directory)): hashlib.sha256(f.read_bytes()).hexdigest()
            for f in sorted(directory.rglob("*")) if f.is_file()}


def assert_same_seed(directory: str, *, package: pathlib.Path | None = None,
                     review: pathlib.Path | None = None) -> str:
    """A digest over the whole seed directory, which both copies must agree on.

    A missing review copy is the same refusal as a differing one. "The
    materialiser cannot see this seed" and "the materialiser sees a different
    seed" both mean the artifacts would not be built from what was read.
    """
    package = PACKAGE if package is None else package
    review = REVIEW if review is None else review

    here = _tree(package / directory)
    there = _tree(review / directory)

    if not here:
        raise SeedCopiesDiverged(
            f"{directory}: the package copy under {package} holds no files")
    if not there:
        raise SeedCopiesDiverged(
            f"{directory}: the materialiser's review copy under {review} is not "
            "there, so the artifacts would be built from something the harness "
            "never read")

    if here != there:
        only_package = sorted(set(here) - set(there))
        only_review = sorted(set(there) - set(here))
        changed = sorted(f for f in set(here) & set(there) if here[f] != there[f])
        detail = []
        if changed:
            detail.append("changed " + ", ".join(
                f"{f} package {here[f][:12]} review {there[f][:12]}" for f in changed))
        if only_package:
            detail.append("only in the package " + ", ".join(only_package))
        if only_review:
            detail.append("only in the review copy " + ", ".join(only_review))
        raise SeedCopiesDiverged(
            f"{directory}: the two copies disagree. " + "; ".join(detail) + ". "
            f"The package is {package} and the review copy is {review}. "
            "Expectations are read from the package and artifacts are built "
            "from the review copy, so this would surface as a candidate failing "
            "a scenario nobody ran."
        )

    return hashlib.sha256(
        "\n".join(f"{name} {here[name]}" for name in sorted(here)).encode()
    ).hexdigest()


def materialize(entry: dict, variant: dict, *, run_root: pathlib.Path) -> Built:
    """Build one second generation variant's artifacts, and hand back bytes.

    Order matters. The two copies are checked BEFORE anything is built, because
    a check that runs afterwards reports on artifacts that already exist and
    someone will read them.

    The payload comes back as bytes so the adapter never opens another seed's
    directory. That is the whole reason the reference is resolved at load time.
    """
    run_root = pathlib.Path(run_root)
    try:
        inside = run_root.resolve().is_relative_to(PRIVATE_TMP)
    except OSError:                                          # pragma: no cover
        inside = False
    if not inside:
        raise UnsafeRunRoot(
            f"{run_root} is not under {PRIVATE_TMP}. These runs create pipes, "
            "child processes and a file observer, and ASTRA's materialiser "
            "refuses anywhere else for the same reason.")

    seed_digest = assert_same_seed(entry["directory"])

    run_root.parent.mkdir(parents=True, exist_ok=True)
    with _astras_evidence_untouched():
        result = subprocess.run(
            [sys.executable, str(MATERIALISER),
             "--seed", entry["directory"],
             "--variant", variant["name"],
             "--run-root", str(run_root)],
            capture_output=True, text=True)
    if result.returncode != 0:
        raise MaterialisationFailed(
            f"{entry['id']}.{variant['name']}: the materialiser exited "
            f"{result.returncode}\n{result.stderr.strip()[-2000:]}")

    missing = [named for named in (variant["requests"], variant["upstream_output"],
                                   variant["schedule_file"])
               if not (run_root / named).is_file()]
    if missing:
        raise MaterialisationFailed(
            f"{entry['id']}.{variant['name']}: the materialiser exited 0 but "
            f"did not write {missing}. Exit status is not the artifact.")

    schedule = json.loads((run_root / variant["schedule_file"]).read_text())
    return Built(run_root=run_root, schedule=schedule,
                 payload=_payload(variant), seed_digest=seed_digest)


def _payload(variant: dict) -> bytes:
    """One resolver, T8's, in `runner`. Imported here to keep the path local."""
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    import runner
    return runner.resolve_payload_ref(variant)


@contextlib.contextmanager
def _astras_evidence_untouched():
    """Put ASTRA's materialisation receipt back exactly as it was.

    The materialiser rewrites `evidence/materialization_validation.json` in its
    own review directory on every call, with only the variant it just built.
    Eight test runs of mine reduced a 74 variant receipt to a single entry
    naming a pytest temp directory, and driving the grid would have done it 95
    times. It is ASTRA's record of THEIR materialisation; nothing about a
    harness run belongs in it, and my own receipts live in the run root.

    Restored on the failure path too. A materialiser that raises has still
    written the file by then in some cases, and "it crashed" is not a reason to
    leave someone else's evidence rewritten.
    """
    receipt = REVIEW_ROOT / "evidence" / "materialization_validation.json"
    try:
        before = receipt.read_bytes()
    except OSError:
        before = None
    try:
        yield
    finally:
        if before is None:
            receipt.unlink(missing_ok=True)
        else:
            receipt.write_bytes(before)

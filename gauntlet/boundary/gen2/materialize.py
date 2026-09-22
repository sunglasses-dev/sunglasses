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
import copy
import dataclasses
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

PACKAGE = pathlib.Path.home() / ".claude" / "state" / "warroom" / "GATE2_SCENARIOS"
REVIEW_ROOT = (pathlib.Path.home() / "Desktop" / "SUNGLASSES_ASTRA_REVIEW_2026-09-04"
               / "GATE3_DESIGN_REVIEW_2026-09-13")
REVIEW = REVIEW_ROOT / "fixtures"
MATERIALISER = REVIEW_ROOT / "materialize_specs.py"

# ASTRA's script refuses a root anywhere else, and it is right to: these runs
# create pipes, children and a file observer, and a fixture root that could
# resolve into a real tree is a fixture that can reach one.
PRIVATE_TMP = pathlib.Path("/private/tmp")

# Where the seeds were built, and where their payload references still point.
# The tree was reaped, as a private temporary tree is supposed to be, and the
# references in scenario.json are frozen absolute paths into it. Every file it
# held also exists under the review root, which is on disk and durable.
REAPED_FIXTURE_ROOT = pathlib.Path("/private/tmp/GATE3_DESIGN_REVIEW_2026-09-13")


class UnsafeRunRoot(Exception):
    """A run root outside the private temporary tree."""


class SeedCopiesDiverged(Exception):
    """The package copy and the materialiser's copy of a seed disagree."""


class MaterialisationFailed(Exception):
    """The materialiser did not produce what the variant names."""


class PayloadReferenceUnresolved(Exception):
    """A payload reference names a file that is gone, with no twin that binds."""


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


def resolved_payload_path(ref: dict, *, where: str) -> pathlib.Path:
    """The file a payload reference means, which is not always the path it names.

    The reference is a frozen absolute path into a private temporary tree that
    no longer exists. Redirecting it is only safe because the reference also
    carries the digest: the twin under the review root is accepted when its
    BYTES hash to what the reference declares, and refused otherwise. So this
    cannot quietly substitute a different payload, which is the only thing that
    would make the run report on a scenario nobody wrote.

    A path that is still there is returned untouched. Resolution is for the
    reaped tree alone; anything else missing is a refusal, because a reference
    outside that tree pointing at nothing is a broken delivery and not a
    reaped one.
    """
    declared = pathlib.Path(ref["path"])
    if declared.is_file():
        return declared

    try:
        relative = declared.relative_to(REAPED_FIXTURE_ROOT)
    except ValueError:
        raise PayloadReferenceUnresolved(
            f"{where}: the payload reference names {declared}, which is not "
            f"there and is not under {REAPED_FIXTURE_ROOT}. Only the reaped "
            "fixture tree is resolved; this is a delivery that lost a file."
        ) from None

    twin = REVIEW_ROOT / relative
    if not twin.is_file():
        raise PayloadReferenceUnresolved(
            f"{where}: the payload reference names {declared}, the tree it "
            f"points into was reaped, and there is no copy at {twin}.")

    got = hashlib.sha256(twin.read_bytes()).hexdigest()
    if got != ref["sha256"]:
        raise PayloadReferenceUnresolved(
            f"{where}: {twin} is where {declared} was, and its bytes are not "
            f"that payload. The reference declares {ref['sha256'][:12]} and the "
            f"file hashes to {got[:12]}. The digest decides, so this refuses "
            "rather than build a variant out of a different payload."
        )
    return twin


def _without_payload_paths(scenario: dict) -> dict:
    """The scenario with every payload path removed, for comparing the rest."""
    bare = copy.deepcopy(scenario)
    for variant in bare.get("variants", []):
        if isinstance(variant.get("payload_ref"), dict):
            variant["payload_ref"].pop("path", None)
    return bare


def _resolved_scenario(delivered_path: pathlib.Path, *, directory: str) -> str:
    """The delivered scenario with its payload paths resolved, and nothing else.

    The comparison at the end is the point. This function edits a document the
    materialiser treats as the contract, so it has to be provable that it
    changed the one field it claims to change. Digests, expectations, sequences
    and the variant list all come through untouched or this refuses.
    """
    delivered = json.loads(delivered_path.read_text())
    resolved = copy.deepcopy(delivered)
    for variant in resolved.get("variants", []):
        ref = variant.get("payload_ref")
        if not isinstance(ref, dict) or "path" not in ref:
            continue
        ref["path"] = str(resolved_payload_path(
            ref, where=f"{directory}.{variant.get('name')}"))

    if _without_payload_paths(delivered) != _without_payload_paths(resolved):
        raise PayloadReferenceUnresolved(
            f"{directory}: resolving the payload references changed something "
            "other than a payload path. Refusing rather than handing the "
            "materialiser a contract it was not given."
        )
    return json.dumps(resolved, ensure_ascii=False, indent=1) + "\n"


@contextlib.contextmanager
def _materialiser_root(directory: str):
    """A root the materialiser can run from whose payload references resolve.

    The script finds its own root by resolving its own path, so it is the one
    thing here that has to be a real copy. Everything else it reads is linked
    to the delivery, which means `expected.json` still resolves to the review
    copy the schedule has always named, and the seed the materialiser builds
    from is still the delivered seed.

    Two files are not links. `scenario.json`, because resolving its payload
    paths is the whole purpose. And `evidence/`, because the materialiser
    writes its receipt there on every call and the delivered receipt is
    ASTRA's record of THEIR run.

    Nothing under the review root is written. The copy is torn down after.
    """
    seed = REVIEW / directory
    if not seed.is_dir():
        raise SeedCopiesDiverged(
            f"{directory}: no such seed under the materialiser's copy {REVIEW}")

    workspace = pathlib.Path(tempfile.mkdtemp(prefix="gen2-materialiser-",
                                              dir=PRIVATE_TMP))
    try:
        shutil.copy2(MATERIALISER, workspace / MATERIALISER.name)
        shutil.copytree(REVIEW_ROOT / "evidence", workspace / "evidence")
        for sibling in REVIEW_ROOT.iterdir():
            if sibling.name in {"evidence", "fixtures", MATERIALISER.name}:
                continue
            (workspace / sibling.name).symlink_to(sibling)

        fixtures = workspace / "fixtures"
        fixtures.mkdir()
        for sibling in REVIEW.iterdir():
            if sibling.name != directory:
                (fixtures / sibling.name).symlink_to(sibling)

        mirror = fixtures / directory
        mirror.mkdir()
        for member in seed.iterdir():
            if member.name != "scenario.json":
                (mirror / member.name).symlink_to(member)
        (mirror / "scenario.json").write_text(
            _resolved_scenario(seed / "scenario.json", directory=directory))

        yield workspace
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


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
    with _materialiser_root(entry["directory"]) as materialiser_root:
        with _astras_evidence_untouched():
            result = subprocess.run(
                [sys.executable, str(materialiser_root / MATERIALISER.name),
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

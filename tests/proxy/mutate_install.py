#!/usr/bin/env python3
"""Prove each control red by the defect it exists to catch. Round 2.

Round 1 shipped 11/11 and then failed 24 of 48 independent property controls.
The reason is written here rather than in a commit nobody re-reads: those
mutations were chosen by reading the implementation, so each one asked whether
the code did what it already did. This battery is rebuilt from the CONTRACT
rows and from every control ASTRA's review found failing, so a row can fail.

Two standing rules this file enforces on itself:

  An anchor is a claim about the source and goes stale like any other. Round 1
  published 11/11 from a run taken before `resolve_artifact()` existed, and on
  the pushed head one anchor matched twice and proved nothing. Anchor
  uniqueness is asserted when this file is generated AND checked again here at
  run time, and an ambiguous anchor is a SURVIVOR, never a skip.

  A kill count on a red baseline is not a kill count, and bytecode is disabled,
  because a cached .pyc ran the previous mutant on 2026-09-14 and produced
  false kills.

    python3 tests/proxy/mutate_install.py
"""
import atexit
import hashlib
import os
import pathlib
import shutil
import tempfile
import re
import subprocess
import sys

# THE TREE THIS MUTATES IS A PRIVATE COPY, and that is the whole of this block.
#
# Until 2026-09-19 the harness rewrote `sunglasses/install.py` IN PLACE. Two things
# followed, and both were paid for on the same night:
#
#   * a kill STRANDS A MUTANT. Interrupt the run between the write and the
#     restore -- a platform budget cut, a Ctrl-C, an OOM -- and the working tree
#     keeps a mutated product. The next battery then refuses with BASELINE IS
#     RED, and that is the LUCKY case; the unlucky one is a reader that trusts
#     the file.
#   * it rewrites a tree OTHER PROCESSES READ. A reviewer working in the same
#     directory saw a mutated product mid-review and its round was void.
#
# So: copy the tree once, mutate the copy, point pytest at the copy. The real
# source is opened for reading and never for writing, and `_assert_source_untouched`
# proves that rather than asserting it in a comment.
SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE_TARGET = SOURCE_ROOT / "sunglasses/install.py"


def _digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


_SOURCE_DIGEST_AT_START = _digest(SOURCE_TARGET)


def _assert_source_untouched(when):
    """Refuse LOUDLY if the real product moved while we ran.

    A silent mismatch is how the in-place version did its damage: nothing said
    anything until a later run found a red baseline and had to work backwards.
    """
    now = _digest(SOURCE_TARGET)
    if now != _SOURCE_DIGEST_AT_START:
        raise SystemExit(
            f"REFUSING: {SOURCE_TARGET} changed {when} this battery "
            f"({_SOURCE_DIGEST_AT_START[:16]} -> {now[:16]}). This harness "
            f"mutates a private copy and must never write the source tree.")


def _sweep_abandoned_copies(prefix, keep_hours=6):
    """Remove OUR OWN older copies, because an uncatchable kill skips `atexit`.

    The copy costs about 18 MB. A kill -9 -- which is exactly the case this
    harness now survives -- leaves it behind, so without this the fix trades a
    corrupted source tree for an unbounded pile of temp trees. The age floor is
    what keeps a CONCURRENT battery safe: a run younger than `keep_hours` is
    never touched, so two harnesses can run at once without eating each other.
    """
    import time
    root = pathlib.Path(tempfile.gettempdir())
    cutoff = time.time() - keep_hours * 3600
    for stale in root.glob(prefix + "*"):
        try:
            if stale.is_dir() and stale.stat().st_mtime < cutoff:
                shutil.rmtree(stale, ignore_errors=True)
        except OSError:
            pass

_sweep_abandoned_copies("mutate-install-")
_WORK = pathlib.Path(tempfile.mkdtemp(prefix="mutate-install-")) / "tree"
shutil.copytree(SOURCE_ROOT, _WORK,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
atexit.register(shutil.rmtree, _WORK.parent, True)

ROOT = _WORK
TARGET = ROOT / "sunglasses/install.py"
# Both files, because round 7's lock is only observable through a control that
# needs a real second process, and that machinery lives in the CLI file. A
# mutation harness that runs one file cannot kill a mutant whose only control
# is in the other: R7-LOCK came back "red but NOT by its control" until this
# line was a list, and red-by-the-wrong-control is a survivor. The atomic
# storage file joins it for the same reason -- ATOMIC-PUBLISH and NOFOLLOW have
# their only controls there.
SUITE = ["tests/proxy/test_install_transaction.py",
         "tests/proxy/test_install_cli.py",
         "tests/proxy/test_install_atomic_storage.py"]

# (id, the defect, old source, mutated source, the control that must fail)
MUTATIONS = [
    ('C1', 'uninstall restores a re-serialisation instead of the retained bytes',
     '        _atomic_write(target, retained)   # byte-exact restore',
     '        _atomic_write(target, (json.dumps(_parse(retained, target), indent=2) + "\\n").encode("utf-8"))',
     'test_uninstall_restores_the_retained_bytes_exactly'),
    ('C2-REPEAT', 'a matching wrapper is a silent no-op instead of a refusal',
     '            if classify(existing, artifact=artifact) == "WRAPPED":\n                raise ConfigConflict(\n                    f"{name!r} is already wrapped in {target}; nothing to do")',
     '            if classify(existing, artifact=artifact) == "WRAPPED":\n                return',
     'test_install_never_wraps_the_wrapper'),
    ('C2-DRIFT', 'only a VERIFIED wrapper stops a re-wrap, so drift nests one',
     '    if isinstance(existing, dict) and MARKER in existing:',
     '    if isinstance(existing, dict) and classify(existing, artifact=artifact) == "WRAPPED":',
     'test_a_wrapper_with_a_changed_digest_is_never_wrapped_again'),
    ('C3', 'the entry-only inverse rebuilds the file and drops unrelated entries',
     '    if record.get("entry_existed", True):\n        servers[name] = record["original_entry"]\n    else:\n        del servers[name]',
     '    doc = {"mcpServers": {name: record["original_entry"]}}\n    servers = doc["mcpServers"]',
     'test_uninstall_does_entry_only_inverse_when_the_file_moved'),
    ('C4-WRITE', 'an interrupted write reports success instead of refusing',
     '        raise ConfigIOError(f"write to {path} was interrupted: {e}") from e',
     '        return',
     'test_interrupted_write_leaves_the_original_intact'),
    ('C4-TEMP', 'an interrupted write leaves its temp file behind',
     '        try:\n            os.unlink(tmp)\n        except OSError:\n            pass\n        raise ConfigIOError(f"write to {path} was interrupted',
     '        raise ConfigIOError(f"write to {path} was interrupted',
     'test_interrupted_write_leaves_no_temp_file_behind'),
    ('C4-STAT', 'a stat fault escapes the typed refusal',
     '        raise ConfigIOError(f"cannot stat {path}: {e}") from e',
     '        raise',
     'test_every_transaction_io_fault_is_one_typed_refusal'),
    ('C4-MKSTEMP', 'a mkstemp fault escapes the typed refusal',
     '        raise ConfigIOError(f"cannot create a temporary file beside {path}: {e}") from e',
     '        raise',
     'test_every_transaction_io_fault_is_one_typed_refusal'),
    ('C4-RECORD', 'a failed record write leaves the target wrapped',
     '        rolled_back = True\n        try:\n            _atomic_write(target, raw)\n        except ConfigIOError:\n            rolled_back = False',
     '        rolled_back = False',
     'test_a_failed_record_write_restores_the_target'),
    ('C5', 'install proceeds when the artifact cannot be resolved',
     '    try:\n        digest = _digest_file(artifact)\n    except OSError as e:\n        raise ArtifactUnresolved(',
     '    try:\n        digest = _digest_file(artifact)\n    except OSError as e:\n        digest = "0" * 64\n    if False:\n        raise ArtifactUnresolved(',
     'test_install_refuses_when_the_artifact_cannot_be_resolved'),
    ('C6-PATH', 'WRAPPED without comparing the artifact path',
     '    if meta.get("artifact") != resolved or meta.get("sha256") != actual:',
     '    if meta.get("sha256") != actual:',
     # Re-pointed: the identical-twin control kills this mutation only via the
     # ARGV binding, which subsumes the marker path check for that case. The
     # control that isolates the marker path is the one below.
     'test_a_marker_naming_a_different_artifact_than_it_launches_is_unverified'),
    ('C6-DIGEST', 'WRAPPED without comparing the artifact digest',
     '    if meta.get("artifact") != resolved or meta.get("sha256") != actual:',
     '    if meta.get("artifact") != resolved:',
     'test_classify_is_content_addressed_not_path_addressed'),
    ('C6-MARKER', 'a command that merely names us counts as wrapped',
     '    if not isinstance(meta, dict):\n        return "DIRECT"',
     '    if not isinstance(meta, dict):\n        return "WRAPPED" if "sunglasses" in repr(entry) else "DIRECT"',
     'test_a_command_that_merely_names_us_is_not_wrapped'),
    ('C6-ARGV', 'WRAPPED without checking the argv that would run',
     '    if not isinstance(args, list) or args[:2] != [resolved, "--"]:\n        return "UNVERIFIED"',
     '    if False:\n        return "UNVERIFIED"',
     'test_wrapped_requires_the_entry_to_actually_launch_the_artifact'),
    ('R5-RETAINED', 'retained bytes are restored without validating their digest',
     '    if _digest_bytes(retained) != record.get("file_sha_before"):',
     '    if False:',
     'test_uninstall_refuses_retained_bytes_that_do_not_match_the_record'),
    ('R5-MISSING', 'a missing retained original escapes as an untyped error',
     '    except OSError as e:\n        raise _RetainedUnusable(ConfigConflict(\n            f"the retained original for {name!r} is missing: {e}")) from e',
     '    except OSError:\n        raise',
     'test_uninstall_refuses_when_the_retained_bytes_are_gone'),
    ('R5-RECTYPE', 'a record that is not an object is accepted',
     '    if not isinstance(record, dict):\n        raise ConfigConflict(f"the record for {name!r} is not an object")',
     '    if False:\n        raise ConfigConflict(f"the record for {name!r} is not an object")',
     'test_uninstall_refuses_a_record_it_cannot_read'),
    ('INVERSE', 'the inverse of creating an entry puts one back instead of removing it',
     '    if record.get("entry_existed", True):\n        servers[name] = record["original_entry"]\n    else:\n        del servers[name]',
     '    servers[name] = record["original_entry"]',
     'test_uninstall_removes_an_entry_that_install_created'),
    ('DUPKEY', 'duplicate JSON keys are collapsed silently instead of refused',
     '        if key in out:\n            raise ValueError(f"duplicate key {key!r}")',
     '        if False:\n            raise ValueError(f"duplicate key {key!r}")',
     'test_install_refuses_duplicate_json_keys_rather_than_dropping_data'),
    ('SHAPE-DOC', 'a non-object document is accepted',
     '    if not isinstance(doc, dict):\n        raise ConfigIOError(f"{path}: the top level is not a JSON object")',
     '    if False:\n        raise ConfigIOError(f"{path}: the top level is not a JSON object")',
     'test_install_refuses_an_invalid_shape_without_mutating'),
    ('SHAPE-ARGS', 'an entry whose args are not a list of strings is accepted',
     '    if args is not None and not (isinstance(args, list)\n                                 and all(isinstance(a, str) for a in args)):',
     '    if False:',
     'test_install_refuses_an_invalid_shape_without_mutating'),
    ('OPTIONS', "wrapping drops the entry's env and cwd",
     '        wrapper = {k: v for k, v in original_entry.items()\n                   if k not in ("command", "args")}',
     '        wrapper = {}',
     'test_wrapping_preserves_the_entrys_execution_options'),
    ('R4-ARGV', 'the -- argv form ignores the supplied argv',
     '        original_entry = {"command": argv[0], "args": list(argv[1:])}',
     '        original_entry = {"command": "npx", "args": []}',
     'test_install_with_argv_creates_and_wraps_a_new_entry'),
    ('MODE', 'the atomic replace does not preserve the file mode',
     '        os.chmod(tmp, mode)',
     '        os.chmod(tmp, 0o600)',
     'test_install_preserves_the_file_mode'),
    ('READ', 'an unreadable config escapes as an untyped error',
     '        raise ConfigIOError(f"cannot read {path}: {e}") from e',
     '        raise',
     'test_install_refuses_an_unreadable_config'),
    ('COLLISION', 'a completed record is overwritten instead of refused',
     '    if rec_path.exists():\n        prior = None',
     '    if False:\n        prior = None',
     'test_install_refuses_while_a_completed_record_is_outstanding'),
    ('C6-EXEC', 'a command that runs nothing is verified by its own marker',
     'if command != meta.get("command") or not _could_execute(command):',
     'if command != meta.get("command"):',
     'test_a_marker_cannot_vouch_for_a_command_that_runs_nothing'),
    ('JOURNAL-RECOVER', 'uninstall ignores an open journal and strands the target',
     '        if pending_path.exists():\n            return _recover_from_journal(target, name, pending_path, home=home)\n        raise ConfigConflict(f"no recorded install for {name!r}")',
     '        if False:\n            return _recover_from_journal(target, name, pending_path, home=home)\n        raise ConfigConflict(f"no recorded install for {name!r}")',
     'test_uninstall_recovers_a_transaction_that_crashed_after_the_replace'),
    ('JOURNAL-GUARD', 'install resumes a journal that captured other bytes',
     '        if _digest_bytes(raw) != journal.get("file_sha_before"):',
     '        if False:',
     'test_install_refuses_a_journal_that_captured_a_different_version'),
    ('PENDING-PARTIAL', 'a half-written journal is left on disk',
     '        _discard(pending_path, bytes_path)\n        raise ConfigIOError(f"cannot write the pending record',
     '        _discard(bytes_path)\n        raise ConfigIOError(f"cannot write the pending record',
     'test_a_half_written_journal_is_removed_not_left_behind'),
    ('ROLLBACK-DURABLE', 'a failed rollback deletes the only way back',
     '        if rolled_back:',
     '        if True:',
     'test_a_failed_rollback_keeps_the_only_way_back'),
    ('RECORD-TYPES', 'a record field of the wrong type is accepted',
     '        if not isinstance(record[field_name], want):',
     '        if False:',
     'test_uninstall_validates_a_record_as_strictly_as_a_config'),
    ('RECORD-REQUIRED', 'a record missing target_path is accepted',
     '        if field_name not in record:\n            raise ConfigConflict(f"the record for {name!r} is missing {field_name}")',
     '        if False:\n            raise ConfigConflict(f"the record for {name!r} is missing {field_name}")',
     'test_uninstall_validates_a_record_as_strictly_as_a_config'),
    ('RECORD-STATE', 'a record in the wrong state is acted on anyway',
     '    if state != expect_state:',
     '    if False:',
     'test_uninstall_validates_a_record_as_strictly_as_a_config'),
    ('RECORD-STRICT', 'a record is parsed more loosely than a config',
     '        record = _strict_loads(raw, f"the record for {name!r}")',
     '        record = json.loads(raw.decode("utf-8"))',
     'test_uninstall_validates_a_record_as_strictly_as_a_config'),
    ('NONFINITE', 'NaN and Infinity are accepted as JSON',
     '                          parse_constant=_reject_constant)',
     '                          )',
     'test_install_refuses_a_config_with_nan'),
    # ── Round 4. One mutation per new guard, so each is proven reachable ────
    ('F1-PATH', 'the retained original is read from any path the record names',
     '    if retained_path != canonical:',
     '    if False:',
     'test_uninstall_refuses_a_record_whose_retained_path_is_not_the_canonical_one'),
    ('F1-SYMLINK', 'the canonical name may be a symlink to somewhere else',
     '    if retained_path.is_symlink():',
     '    if False:',
     'test_uninstall_refuses_when_the_canonical_retained_path_is_a_symlink'),
    # ── Round 5. ASTRA's four families, one mutation per new guard ─────────
    ('R5-STRANDED', 'an unreadable completed record masks a valid journal',
     '        if pending_path.exists():\n            return _recover_from_journal(target, name, pending_path, home=home)\n        raise\n',
     '        if False:\n            return _recover_from_journal(target, name, pending_path, home=home)\n        raise\n',
     'test_uninstall_recovers_from_the_journal_when_the_completed_record_is_unreadable'),
    ('R5-RECONCILE', 'journal recovery overwrites an edit made after the crash',
     '    installed = _installed_rendering(retained, name, journal)\n    if installed is not None and current == installed:',
     '    installed = _installed_rendering(retained, name, journal)\n    if True:',
     'test_journal_recovery_refuses_a_target_edited_since_the_crash'),
    ('R5-SYMLINK-STORAGE', 'a symlink at one of our record names is written through',
     '    _refuse_symlinked_storage(name, rec_path, pending_path, bytes_path)',
     '    pass',
     'test_install_refuses_when_a_symlink_occupies_a_record_name'),
    ('R5-AFTER-TYPE', 'a complete record with a non-digest after-image is trusted',
     '    if expect_state == "complete" and not _is_digest(after):',
     '    if False:',
     'test_uninstall_refuses_a_complete_record_whose_after_digest_is_not_a_digest'),
    ('R5-EXISTED-TYPE', 'entry_existed is read as a truth value whatever its type',
     '    if not isinstance(record["entry_existed"], bool):',
     '    if False:',
     'test_uninstall_refuses_a_record_whose_entry_existed_is_not_a_bool'),
    # ── Round 6. ASTRA's two recovery races, one mutation per guard ────────
    ('R6-CLAIMED', 'cleanup deletes retained bytes another record still claims',
     '        if q.with_suffix(".json").exists():',
     '        if False:',
     'test_discard_never_removes_a_retained_original_a_record_still_claims'),
    ('R7-TAKE-FIRST', 'cleanup unlinks the NAME instead of the bytes it took',
     '            q.rename(held)',
     '            held = q',
     'test_discard_takes_the_retained_bytes_before_it_asks_about_them'),
    ('R7-ABA', 'a declared write accepts the same bytes in a different file',
     '            if expect_identity is not None and identity != expect_identity:',
     '            if False:',
     'test_a_declared_write_refuses_bytes_that_are_the_same_file_no_longer'),
    ('R7-CANCELLED', 'an install cancelled while it wrote still reports success',
     '    if not (_still_ours(bytes_path, identities["retained"])',
     '    if False and (_still_ours(bytes_path, identities["retained"])',
     'test_an_install_cancelled_while_it_writes_does_not_report_success'),
    ('R8-REDERIVE', 'a writer publishes what it rendered before it waited',
     '                if now != seen:',
     '                if False:',
     'test_a_writer_that_read_before_the_lock_re_derives_under_it'),
    ('R8-INVERSE-LAST', 'a refused rollback leaves the wrapper with no inverse',
     '                if usable:\n                    spare_record.rename(rec_path)',
     '                if False:\n                    spare_record.rename(rec_path)',
     'test_a_cancelled_install_whose_rollback_refuses_still_has_an_inverse'),
    ('R10-STANDBY-VALIDATED', 'a standby is promoted without checking its bytes',
     '                usable = _digest_file(spare_bytes) == record["file_sha_before"]',
     '                usable = True',
     'test_a_standby_whose_bytes_no_longer_match_is_not_promoted'),
    ('R10-ADOPT', 'a standby left by a dead publisher is never discovered',
     '    _adopt_standby(home, name, target)',
     '    pass',
     'test_a_standby_left_by_an_ended_publisher_is_discovered'),
    ('R10-NOTE-ATOMIC', 'the take note is claimed without O_EXCL',
     '        if not _claim_take_note(taking, intent):',
     '        if False:',
     'test_a_second_cleanup_does_not_remove_the_first_cleanups_note'),
    # The mutant RESTORES round 9's shape rather than deleting the line. A
    # `pass` here empties the control's barrier and the row dies on its setup,
    # which is a kill from an unfilled barrier and not a kill at all -- the
    # reviewer counted it against us and was right (R-177-R11 (e)).
    ('R10-FORGET-ATOMIC', 'the note is unlinked by path instead of taken first',
     '        taking.rename(private)',
     '        private = taking',
     'test_a_new_owners_note_survives_an_older_cleanups_forget'),
    ('R11-PUTBACK-NAME', 'the put-back overwrites a new owner by renaming onto the name',
     '        os.link(str(private), str(taking))',
     '        private.rename(taking)',
     'test_a_put_back_loses_to_a_new_owner_of_the_name'),
    # ANCHORED ON THE POINT-OF-USE CHECK, not the gate above it. Round 12 added
    # a second authorisation immediately before the write, so disabling the
    # first one alone changes nothing and the mutant survived its own control --
    # correctly. The authority is where the decision is acted on.
    # ROUND 13 RE-POINTED THIS ANCHOR. The gate did not go away: the
    # authorisation it takes is now a DESCRIPTOR held across the write
    # (`_authorise_from_one_fd`), so the call text changed in the same edit.
    # An anchor that goes stale does not fail loudly, it fails to APPLY -- the
    # harness then reports a kill for a mutant it never introduced -- which is
    # why the presence row above is part of the suite and not a convenience.
    ('R11-NO-FIELD', 'a record field decides that an entry-only restore is allowed',
     '        authority = _authorise_from_one_fd(record, name, home=home)\n        if authority is None:\n            raise retained_failure',
     '        authority = _authorise_from_one_fd(record, name, home=home)\n        if False:\n            raise retained_failure',
     'test_evidence_swapped_after_the_gate_does_not_license_the_restore'),
    ('R11-ADOPT-CURRENT', 'the oldest standby pair is adopted instead of the live one',
     '        if not _is_digest(after) or after != _digest_bytes(live):',
     '        if False:',
     'test_the_standby_that_describes_the_live_file_is_the_one_adopted'),
    ('R9-INVERSE-FIRST', 'the inverse is only in memory until the rebuild needs it',
     '        stand_by(new_raw, raw)',
     '        pass',
     'test_the_inverse_is_on_disk_before_the_wrapper_it_undoes'),
    ('R9-NOTE-SHAPE', 'a note that is not an object reaches .get',
     '    if not isinstance(intent, dict):\n        raise ConfigConflict(',
     '    if False:\n        raise ConfigConflict(',
     'test_a_leftover_is_not_reclaimed_on_the_strength_of_its_name'),
    # R9-NOTE-OWNERSHIP RETIRED IN ROUND 10, deliberately and not quietly.
    # `_note_is_live` was the protection in round 9; round 10 made the claim
    # atomic with O_EXCL (R10-NOTE-ATOMIC below), so the old check is a fast
    # path whose answer nothing acts on. A mutation of it cannot fail, and a
    # mutation that cannot fail is a kill counted for nothing.
    ('R8-TAKE-NOTE', 'the take is made without saying what moved where',
     '        taking.write_text(intent, encoding="utf-8")',
     '        pass',
     'test_bytes_taken_by_an_interrupted_cleanup_are_reclaimed_by_digest'),
    ('R8-TAKE-DIGEST', 'a leftover is reclaimed on the strength of its name',
     '        if _digest_file(held) != expected:',
     '        if False:',
     'test_a_leftover_is_not_reclaimed_on_the_strength_of_its_name'),
    ('R7-LOCK', 'the compare and the rename stop being one step',
     '        with _exclusive(_LOCK_FOR.get(str(p))):',
     '        with _exclusive(None):',
     'test_a_racing_install_that_can_wait_survives_our_rename'),
    ('R6-CAS', 'a declared write overwrites a target that changed underneath',
     '            if _digest_bytes(current) != expect_sha:',
     '            if False:',
     'test_a_declared_write_refuses_when_the_target_changed_underneath'),
    # ── The deferred row (R-177-R5a): one mutation per new guard ───────────
    ('ATOMIC-PUBLISH', 'the completed record is written straight to its own name',
     '    tmp = _temp_beside(path)\n    _write_private(tmp, data, what=f"the temporary {what}")',
     '    tmp = _temp_beside(path)\n    _write_private(path, data, what=f"the temporary {what}")\n    tmp = path',
     'test_a_killed_completion_never_publishes_an_unparseable_record'),
    ('NOFOLLOW', 'the writer follows a symlink at one of our own names',
     '                       os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,',
     '                       os.O_WRONLY | os.O_CREAT | os.O_TRUNC,',
     'test_the_retained_writer_itself_refuses_a_symlink'),
    ('F2-EXACT', 'a command that merely names a python verifies a route',
     '    return isinstance(command, str) and command == sys.executable',
     '    return isinstance(command, str) and (command == sys.executable or pathlib.Path(command).name.lower().startswith("python"))',
     'test_a_command_that_merely_names_a_python_is_unverified_not_wrapped'),
]


def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, "-B", "-m", "pytest", *SUITE, "-q", "--no-header",
         "-p", "no:cacheprovider"],
        cwd=str(ROOT), env=env, capture_output=True, text=True)


# A failure that is ABOUT THE SETUP rather than about the product. Each of these
# means the row never reached the thing it is named for, so its redness is the
# harness talking to itself.
# DELIBERATELY NOT exception types. A mutant that removes a type check makes the
# product leak an `AttributeError` or a `TypeError` through a public call, and
# the control that pins the typed refusal is red FOR THAT REASON -- that is the
# defect, not an instrument fault. Four real kills were flagged as fake by a
# version of this list that named those types. What marks a kill as fake is the
# row failing on its OWN bookkeeping: a barrier that never filled, a child that
# never started, a fixture or import that never resolved.
_NOT_BEHAVIOURAL = (
    "ImportError", "ModuleNotFoundError", "Failed: Timeout", "error: fixture",
    "not reached", "never reached", "never fired", "never started",
    "did not complete", "barrier not", "boundary not", "was not reached",
    "never ran",
)


def _why_it_failed(stdout, control):
    """The reason `control` went red, when that reason is not behaviour."""
    block = []
    seen = False
    for line in stdout.splitlines():
        if line.startswith("_" * 5) and control in line:
            seen = True
            block = []
            continue
        if seen and line.startswith("_" * 5):
            break
        if seen:
            block.append(line)
    # ONLY the assertion that actually fired. The first version of this read
    # the whole failure block and flagged real kills, because a row's other
    # assertion messages ("the boundary was never reached") and its fixture
    # names live in that block too. What a row says about itself is not what
    # went wrong.
    fired = next((l for l in block if l.startswith("E ")), "")
    for marker in _NOT_BEHAVIOURAL:
        if marker in fired:
            return marker
    # R12: a BARE assertion with no message, on an empty container or a falsy
    # constant, is a row checking its own bookkeeping -- `assert fired`,
    # `assert hit`, `assert published`. Nothing about the product is stated, so
    # a mutant that empties that flag has not been killed by anything. The
    # reviewer wrote `E       assert []` and round 11 counted it as a kill.
    bare = fired[1:].strip()
    if re.fullmatch(r"assert (\[\]|\{\}|\(\)|False|None|0|''|\"\")", bare):
        return "bare setup assertion"
    return None


def main():
    _assert_source_untouched("before the baseline")
    original = TARGET.read_text()

    base = run()
    if base.returncode != 0:
        print("BASELINE IS RED. A kill count on a red suite is not a kill count.")
        print(base.stdout[-2500:])
        return 1
    print(f"baseline GREEN — {base.stdout.strip().splitlines()[-1]}\n")

    killed, survived = [], []
    for mid, why, old, new, control in MUTATIONS:
        hits = original.count(old)
        if hits != 1:
            print(f"  {mid:12} ANCHOR LOST ({hits} matches) — proves nothing")
            survived.append((mid, why, f"anchor x{hits}"))
            continue
        TARGET.write_text(original.replace(old, new))
        try:
            r = run()
        finally:
            TARGET.write_text(original)

        fails = [l.split("::")[-1].split()[0].split("[")[0]
                 for l in r.stdout.splitlines() if l.startswith("FAILED")]
        if r.returncode != 0 and control in fails:
            # R-177-R11 (e): ONLY BEHAVIOURAL KILLS COUNT. A mutant that empties
            # its control's barrier, or breaks an attribute the control reaches
            # for, makes the row red without saying anything about the product.
            # The reviewer counted one of those against us and was right.
            reason = _why_it_failed(r.stdout, control)
            if reason:
                print(f"  {mid:12} red by {control} but NOT behaviourally "
                      f"— {reason}")
                survived.append((mid, why, f"not behavioural: {reason}"))
            else:
                print(f"  {mid:12} KILLED by {control}  ({len(fails)} failed)")
                killed.append(mid)
        elif r.returncode != 0:
            print(f"  {mid:12} red but NOT by {control} — fails: {sorted(set(fails))[:3]}")
            survived.append((mid, why, "wrong control"))
        else:
            print(f"  {mid:12} SURVIVOR — {why}")
            survived.append((mid, why, "survived"))

    assert TARGET.read_text() == original, "target not restored"
    _assert_source_untouched("after the last mutant")
    print(f"\nkilled {len(killed)}/{len(MUTATIONS)}")
    if survived:
        print("\nSURVIVORS (each one is a gap):")
        for mid, why, how in survived:
            print(f"  {mid}: {why}  [{how}]")
        return 1
    print("every mutation killed by its own control")
    return 0


if __name__ == "__main__":
    sys.exit(main())

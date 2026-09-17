"""T10.R4/R5/R6 — wire an MCP server entry to this artifact, and unwire it.

Contract rows: GATE3_CONTRACT_v5_2026-09-13.md T10.R4, T10.R5, T10.R6.
Round 2, rebuilt against ASTRA's NO GO on 0c184de and T9's ruling R-177-R2.

Round 1 passed 16 of its own mutations and failed 24 of 48 independent property
controls. The gap was not effort, it was that the mutations were chosen from the
implementation, so they asked whether the code did what it already did. These
notes record the properties the controls actually check, because they are the
ones a later edit will quietly break.

**The record is bound to the target it describes.** `installs/<name>.json` is
keyed by name alone, so the same name installed into a second config used to
overwrite the first record and its retained bytes, and uninstalling the first
file then restored the second file's original. A record carries `target_path`
and a name occupied by another target is refused.

**Retained bytes are validated before they are restored.** Round 1 recorded
`file_sha_before` and never read it, so altering the `.original` file made
uninstall copy corrupted bytes into the config and report byte-exact success.
That was reachable from the public CLI with no proxy involved. Retention is now
checked against the recorded digest and a mismatch is a refusal.

**Replace and record are one recoverable transaction.** A pending record is
written first, then the target is replaced, then the record is completed. If
completion fails the target is rolled back to the retained bytes, so the
original-intact outcome holds on a catchable fault rather than leaving a changed
target with no record to undo it.

**An existing wrapper is never wrapped again.** Round 1 only skipped re-wrapping
when the wrapper verified against the current artifact, so a changed digest or a
byte-identical artifact at another path nested a second wrapper. Any marker at
all is now a stop: verified means refuse as already installed, anything else
means refuse as unverifiable.

**WRAPPED is bound to what the entry executes.** Matching metadata is not
enough. The command and the leading argv must actually launch the recorded
artifact, or the route is UNVERIFIED.

**Every fault and every bad shape refuses before mutating.** Operational errors
are one type across the whole transaction boundary so the CLI can return 2
rather than leaking a traceback, duplicate JSON keys are rejected instead of
silently collapsed, and execution options the entry carries are preserved.
"""
import contextlib
import errno
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import time

MARKER = "x-sunglasses"

# The five fields T10.R4 names. A record may carry more, never fewer.
RECORD_FIELDS = ("original_entry", "installed_entry", "file_sha_before",
                 "file_sha_after", "original_bytes_path")


class ConfigConflict(Exception):
    """Unknown or conflicting state (R5). Never mutates."""


class ConfigIOError(Exception):
    """Unusable input, or an interrupted write (R6). Original left intact."""


class ArtifactUnresolved(Exception):
    """The artifact we were asked to wire cannot be resolved (C5)."""


class UninstallResult:
    """`byte_exact` False means the entry was restored but the file is not
    byte-identical, which R5 requires us to report rather than paper over."""

    __slots__ = ("byte_exact",)

    def __init__(self, byte_exact):
        self.byte_exact = byte_exact


def _digest_bytes(b):
    return hashlib.sha256(b).hexdigest()


def _digest_file(p):
    return _digest_bytes(pathlib.Path(p).read_bytes())


def _reject_constant(name):
    """`NaN`, `Infinity` and `-Infinity` are Python's extensions to JSON, not
    JSON. `json.loads` accepts them by default, so a config carrying one parsed
    fine and then round-tripped into a file no other reader can use. Refusing is
    the same rule as duplicate keys: we do not silently accept a grammar the
    user's other tools will reject."""
    raise ValueError(f"{name} is not JSON")


def _strict_loads(raw, what):
    """One loader for every document we read, config or record.

    A record is as untrusted as a config: it is a file on disk that anything can
    edit, and it tells us which bytes to write into the user's configuration.
    Reading it with a laxer parser than the config was read with is how a
    document we refused to accept comes back in through the recovery path.
    """
    try:
        text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys,
                          parse_constant=_reject_constant)
    except RecursionError as e:
        raise ConfigIOError(f"{what} is nested too deeply to parse") from e
    except (ValueError, UnicodeDecodeError) as e:
        raise ConfigIOError(f"{what} is not usable JSON: {e}") from e


def _reject_duplicate_keys(pairs):
    """A duplicate key makes the document ambiguous and `json.loads` resolves it
    silently by keeping the last one. Rewriting such a file drops data the user
    can still see in their own config, so it is refused instead."""
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _read_bytes(path):
    try:
        return pathlib.Path(path).read_bytes()
    except OSError as e:
        raise ConfigIOError(f"cannot read {path}: {e}") from e


def _identity(path):
    """(st_dev, st_ino): which file this is, as distinct from what it says."""
    st = os.stat(str(path))
    return (st.st_dev, st.st_ino)


def _still_ours(path, identity):
    """True only if `path` is still the very file we put there."""
    try:
        return _identity(path) == identity
    except OSError:
        return False


def _read_bytes_and_identity(path):
    """Bytes and file identity taken from ONE descriptor, so they describe the
    same file and not two files that happened to share a path.

    R7-ABA (ASTRA round 6, `R6_TWO_RECOVERIES_ABA`). Content is not identity. A
    second process uninstalled and installed again while a recovery was in
    flight; the new install re-rendered the SAME BYTES the crashed transaction
    had written, so a digest comparison saw an unchanged file that had in fact
    been replaced twice, and the stale recovery overwrote a completed install.
    A -> B -> A is invisible to a hash and obvious to an inode: every
    publication here is a rename, so the inode moves even when the bytes do not.
    """
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError as e:
        raise ConfigIOError(f"cannot open {path}: {e}") from e
    try:
        st = os.fstat(fd)
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError as e:
        raise ConfigIOError(f"cannot read the contents of {path}: {e}") from e
    finally:
        os.close(fd)
    return b"".join(chunks), (st.st_dev, st.st_ino)


def _parse(raw, path):
    return _strict_loads(raw, str(path))


def _servers(doc, path):
    if not isinstance(doc, dict):
        raise ConfigIOError(f"{path}: the top level is not a JSON object")
    servers = doc.get("mcpServers")
    if not isinstance(servers, dict):
        raise ConfigIOError(f"{path}: no mcpServers object")
    return servers


def _validate_entry(entry, name, path):
    """Shape of the entry we are about to read and rewrite. Checked before any
    mutation so a malformed entry is a typed refusal, not a traceback."""
    if not isinstance(entry, dict):
        raise ConfigIOError(f"{path}: the {name!r} entry is not an object")
    command = entry.get("command")
    if not isinstance(command, str) or not command:
        raise ConfigIOError(f"{path}: the {name!r} entry has no string command")
    args = entry.get("args")
    if args is not None and not (isinstance(args, list)
                                 and all(isinstance(a, str) for a in args)):
        raise ConfigIOError(f"{path}: the {name!r} args are not a list of strings")


class _Changed(Exception):
    """Internal: the target moved under a compare-and-swap. Never escapes."""


# path -> digest a caller expects to be overwriting. Dynamically scoped by
# `_expect_unchanged` rather than passed, for the reason in `_atomic_write`.
# Single-threaded by contract: this is a CLI transaction, one per process.
_EXPECTED: dict = {}


@contextlib.contextmanager
def _expect_unchanged(path, sha, identity=None):
    """Declare what the next write to `path` is entitled to overwrite.

    `identity` is the (st_dev, st_ino) the caller read those bytes from. It is
    optional only so that a caller with nothing but a digest still gets the
    content check; every caller inside this module supplies it, and without it
    the comparison cannot see A -> B -> A (see `_read_bytes_and_identity`).
    """
    key = str(path)
    prior = _EXPECTED.get(key)
    _EXPECTED[key] = (sha, identity)
    try:
        yield
    finally:
        if prior is None:
            _EXPECTED.pop(key, None)
        else:
            _EXPECTED[key] = prior


# How long a config transaction will wait for another one to finish before it
# refuses. Bounded ON PURPOSE: a transaction that waits forever is a transaction
# that can hang a user's install because some other process died holding a lock.
_LOCK_WAIT_SECONDS = 5.0

try:
    import fcntl
except ImportError:                                    # pragma: no cover - posix here
    fcntl = None

# Which primitive serialises config transactions on THIS platform, named rather
# than discovered, so a reader and `doctor` can both see it. README promises Mac,
# Windows and Linux; `fcntl` is POSIX-only, and an ImportError swallowed in
# silence would leave Windows with an unserialised transaction that LOOKS
# serialised. It is not silent: on a platform without `flock` the compare-and-swap
# still runs and the narrow race that needs the lock stays open, and that is a
# stated limitation with a control on it rather than a hidden one.
LOCKING = "flock" if fcntl is not None else None

# path -> depth, for the re-entrancy in `_exclusive`.
_HELD: dict = {}

# target path -> the lock file that serialises transactions on it. Dynamically
# scoped for the SAME reason as `_EXPECTED`: the reviewer's race barrier
# replaces `_atomic_write` with a two-positional stub, so anything that reaches
# the rename as an argument turns his instrument into a TypeError instead of a
# refusal. It travels beside the expectation and arrives at the same instant.
_LOCK_FOR: dict = {}


@contextlib.contextmanager
def _locked_for(path, lock_path):
    """Declare which lock the next write to `path` must hold."""
    key = str(path)
    prior = _LOCK_FOR.get(key)
    _LOCK_FOR[key] = lock_path
    try:
        yield
    finally:
        if prior is None:
            _LOCK_FOR.pop(key, None)
        else:
            _LOCK_FOR[key] = prior


@contextlib.contextmanager
def _exclusive(lock_path):
    """Serialise config transactions on one target, or refuse in bounded time.

    R7-CHECK-RENAME-GAP (ASTRA round 6, `R6_CHECK_RENAME_GAP`). The
    compare-and-swap compares and then renames, and his barrier sits INSIDE the
    rename: the one instant left after the comparison. No amount of moving the
    check closes it, because the gap is not where the check is, it is that a
    check and a rename are two operations. Two operations become one only under
    mutual exclusion, so this is the narrowest lock that makes them one.

    Narrow in scope (the compare and the replace, nothing else) and bounded in
    time (`_LOCK_WAIT_SECONDS`, then a typed refusal). A lock that can be waited
    on forever trades a rare lost install for a hang, which is a worse bargain.
    """
    if lock_path is None or LOCKING is None:
        # No registered lock (a direct `_atomic_write`, or a platform without
        # `flock`). The compare-and-swap below still runs; what is missing is
        # the serialisation that makes the compare and the rename one step.
        yield
        return
    key = str(lock_path)
    if _HELD.get(key):
        # Re-entrant ON PURPOSE. The transaction takes this lock, and the write
        # inside it takes the same one; `flock` is per open file description,
        # so a second `open` in this very process would block on a lock this
        # process already holds. One transaction per process is the contract
        # (see `_EXPECTED`), so a depth count is the whole of what re-entrancy
        # means here.
        _HELD[key] += 1
        try:
            yield
        finally:
            _HELD[key] -= 1
        return
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(str(lock_path), "a+")
    except OSError as e:
        raise ConfigIOError(
            f"cannot create the transaction lock at {lock_path}: {e}") from e
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    try:
        while True:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EACCES, errno.EAGAIN):
                    raise ConfigIOError(
                        f"cannot take the transaction lock {lock_path}: {e}"
                    ) from e
                if time.monotonic() >= deadline:
                    raise ConfigIOError(
                        f"another transaction has held {lock_path} for more "
                        f"than {_LOCK_WAIT_SECONDS:g}s; refusing rather than "
                        f"waiting any longer") from None
                time.sleep(0.01)
        _HELD[key] = 1
        try:
            yield
        finally:
            _HELD.pop(key, None)
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def _atomic_write(path, data: bytes):
    """Replace in place, preserving mode. On failure the original is untouched
    and no temp file is left behind (R6). Every OSError on this boundary becomes
    ConfigIOError, including the stat and the mkstemp.

    A caller inside `_expect_unchanged` makes the replace a COMPARE-AND-SWAP,
    checked immediately before the rename rather than by the caller. It travels
    out of band rather than as an argument ON PURPOSE: the reviewer's race
    barrier substitutes this function with a two-positional stub, and adding a
    keyword would raise TypeError inside his instrument, which reads as a broken
    harness rather than as a refusal. The expectation must reach the rename
    without changing the shape of the call that reaches it.

    R5-RECOVERY-OTHER-RACE (ASTRA round 5). A recovery had validated that the
    target was the wrapper it wrote, then paused here while a second install
    added ANOTHER server to the same file and succeeded. The recovery resumed
    and wrote its stale whole-file original over that second wrapper, reporting
    success, and the second install was gone while its record stayed behind.
    The caller's check cannot close that window, because the window is INSIDE
    this call: anything it verified is already old news by the time we rename.
    Whoever knows what they expect to overwrite says so, and the comparison
    happens at the last instant that can still refuse.
    """
    p = pathlib.Path(path)
    try:
        mode = p.stat().st_mode & 0o777
    except OSError as e:
        raise ConfigIOError(f"cannot stat {path}: {e}") from e
    try:
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".sg-", suffix=".tmp")
    except OSError as e:
        raise ConfigIOError(f"cannot create a temporary file beside {path}: {e}") from e
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        with _exclusive(_LOCK_FOR.get(str(p))):
            expectation = _EXPECTED.get(str(p))
            if expectation is not None:
                expect_sha, expect_identity = expectation
                # The last instant at which refusing is still free.
                current, identity = _read_bytes_and_identity(p)
                if _digest_bytes(current) != expect_sha:
                    raise _Changed(
                        f"{path} changed while this transaction was in flight, "
                        f"so writing would discard work that completed after we "
                        f"looked")
                if expect_identity is not None and identity != expect_identity:
                    raise _Changed(
                        f"{path} holds the bytes this transaction expected but "
                        f"is no longer the same file, so it was replaced and "
                        f"replaced back while we were in flight; writing would "
                        f"discard the work that put those bytes there")
            os.replace(tmp, str(p))
    except _Changed as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise ConfigConflict(str(e)) from None
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise ConfigIOError(f"write to {path} was interrupted: {e}") from e
    except ConfigIOError:
        # The re-read and the lock both raise this from INSIDE the try, and
        # neither clause above catches it, so before round 7 either one left a
        # `.sg-*.tmp` behind while this docstring promised none. Same shape as
        # everything else this round: the promise was in the prose and not in a
        # clause.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _refuse_symlinked_storage(name, *paths):
    """Refuse BEFORE any mutation if a symlink occupies one of our own names.

    F1-JOURNAL-RETRY-SYMLINK (ASTRA round 4). `_retained_of` guarded both
    uninstall paths; the install RETRY path never called it and then wrote
    through `write_bytes`, which follows a symlink planted at the canonical
    retained name and overwrote an unrelated file with exit 0. Guarding the
    READERS of a resource is not guarding the resource.

    The check lives HERE, before any mutation, rather than at the write, for
    two reasons. It preserves the unrelated file AND the recovery state,
    because the journal is discarded further down and a refusal after that
    point would strand it. And it leaves the write itself as an ordinary
    `write_bytes`/`write_text`, which is what the reviewer's crash driver
    injects SIGKILL into by patching `Path.write_text` and `Path.write_bytes`
    keyed on the record filenames. An `O_NOFOLLOW` writer closes the same hole
    and makes four of the sixteen crash phases unreachable, so the fault can no
    longer be tested; see the note in the PR body. Refusing early is the fix
    that does not break the instrument that proves it.
    """
    for path in paths:
        if pathlib.Path(path).is_symlink():
            raise ConfigConflict(
                f"{path} is a symlink; the install record directory for "
                f"{name!r} must hold real files, so refusing rather than "
                f"writing through it to somewhere we were not asked to touch")


def _lock_path(home, target):
    """Where the transaction lock for `target` lives.

    NOT beside the target. `test_install_never_writes_outside_the_named_config`
    hashes the whole project tree and allows exactly one file to change, and it
    is right to: the user's project is not ours to drop files in. So the lock
    lives in OUR home, keyed by the resolved target path.

    The limitation that follows is stated rather than hidden: two transactions
    running under DIFFERENT `SUNGLASSES_HOME` values lock different files and do
    not serialise against each other. A lock in a shared world-writable place
    would serialise them and hand any local user a way to block installs by
    squatting the path, which is the worse trade.
    """
    digest = hashlib.sha256(str(pathlib.Path(target).resolve()).encode("utf-8"))
    return pathlib.Path(home) / "proxy" / "locks" / f"{digest.hexdigest()}.lock"


def _record_paths(home, name):
    d = pathlib.Path(home) / "proxy" / "installs"
    return d, d / f"{name}.json", d / f"{name}.pending", d / f"{name}.original"


def _records_dir(home, name):
    d, *rest = _record_paths(home, name)
    try:
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(str(d), 0o700)
    except OSError as e:
        raise ConfigIOError(f"cannot prepare {d}: {e}") from e
    return (d, *rest)


def _discard(*paths):
    """Remove our own transaction files, and NEVER one that is in use.

    R5-RECOVERY-RETRY-RACE (ASTRA round 5). A recovery that had already read and
    validated everything paused here, a SECOND install of the same name
    completed in another process and published its own record and retained
    original, and this loop then deleted that NEW retained original by path and
    reported a byte-identical success. The target was left wrapped by an install
    whose inverse we had just destroyed, and the later uninstall exited 2 with
    nothing to restore from.

    The check has to live HERE and not in the caller: the caller's view of the
    directory is from BEFORE the concurrent install: whatever it re-read a line
    earlier is already stale by the time the unlink happens. This runs at the
    moment of the unlink, which is the only moment that can see the truth.

    So: the retained original belongs to whatever record currently claims it. A
    completed record beside it means it is that install's only way back, and it
    is not ours to remove. Records are removed BEFORE retained bytes in the same
    call, so a caller discarding its own complete transaction is unaffected.
    """
    ordered = sorted(
        (pathlib.Path(x) for x in paths),
        key=lambda q: q.suffix == ".original")      # records first, bytes last
    for q in ordered:
        if q.suffix != ".original":
            try:
                q.unlink()
            except OSError:
                pass
            continue
        # R7-OWNER-CHECK-UNLINK (ASTRA round 6, `R6_OWNER_CHECK_UNLINK_GAP`).
        # Round 6 asked whether a record claimed these bytes and then unlinked
        # the path, and he paused it between the two: a second install completed
        # in that gap, published its own retained original at this very name,
        # and the unlink removed THAT. Checking closer to the unlink does not
        # help, because a check and an unlink are two operations on a NAME.
        #
        # So take the bytes before asking about them. The rename is atomic, and
        # afterwards we hold an inode rather than a name, which is the only
        # thing an unlink can be sure about. If a record does claim them we put
        # them back, and if the slot has been refilled by whoever wrote that
        # record, the copy we are holding is the superseded one and ours to drop.
        held = q.with_name(q.name + f".discarding-{os.getpid()}-{id(q):x}")
        try:
            q.rename(held)
        except OSError:
            continue
        if q.with_suffix(".json").exists():
            # Somebody's completed install is relying on these bytes.
            try:
                if q.exists():
                    held.unlink()
                else:
                    held.rename(q)
            except OSError:
                pass
            continue
        try:
            held.unlink()
        except OSError:
            pass


# Every field a record must carry, with the type it must have. `target_path` is
# REQUIRED: a record that does not say which file it describes cannot be checked
# against the file in front of us, and R5-RECORD-TARGET-REQUIRED showed a record
# with it deleted being applied to a file it was never taken from.
RECORD_TYPES = {
    "original_entry": dict,
    "installed_entry": dict,
    "file_sha_before": str,
    "original_bytes_path": str,
    "target_path": str,
}


def _is_digest(value) -> bool:
    """A sha256 hexdigest and nothing that merely resembles one."""
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _read_record(path, name, *, expect_state):
    """Read and validate a record, or refuse.

    A record is a file on disk that tells us which bytes to write into the
    user's configuration, so it is validated exactly as strictly as a config:
    same parser, required fields, required types, and a state that has to be the
    one we are reading it for. Anything else is CONFIG_CONFLICT with no mutation
    rather than an exception from three frames deeper.
    """
    try:
        raw = pathlib.Path(path).read_bytes()
    except OSError as e:
        raise ConfigConflict(f"the record for {name!r} could not be read: {e}") from e
    try:
        record = _strict_loads(raw, f"the record for {name!r}")
    except ConfigIOError as e:
        raise ConfigConflict(str(e)) from e
    if not isinstance(record, dict):
        raise ConfigConflict(f"the record for {name!r} is not an object")
    for field_name, want in RECORD_TYPES.items():
        if field_name not in record:
            raise ConfigConflict(f"the record for {name!r} is missing {field_name}")
        if not isinstance(record[field_name], want):
            raise ConfigConflict(
                f"the record for {name!r} has a {field_name} that is not a "
                f"{want.__name__}")
    if "file_sha_after" not in record:
        raise ConfigConflict(f"the record for {name!r} is missing file_sha_after")
    # R5-AFTER-NULL / R5-AFTER-LIST / R5-EXISTED-LIST (ASTRA round 4). Presence
    # was checked and TYPE was not, so a record carrying `null` or `[]` for the
    # after-digest was accepted and restoration proceeded through the inverse.
    # A COMPLETE record has always been through the replace, so its after-digest
    # is a digest; a PENDING one has not, so `null` there is a state and not a
    # defect, which is why only the complete case is strict.
    after = record["file_sha_after"]
    if expect_state == "complete" and not _is_digest(after):
        raise ConfigConflict(
            f"the record for {name!r} is marked complete but its file_sha_after "
            f"is not a sha256 digest; refusing to restore from a record whose "
            f"own after-image we cannot read")
    # `entry_existed` decides between putting an entry BACK and DELETING it, so
    # an unvalidated one is a delete waiting to happen: a list is falsey, and an
    # entry that existed before the install was removed on uninstall with exit 0.
    if "entry_existed" not in record:
        raise ConfigConflict(f"the record for {name!r} is missing entry_existed")
    if not isinstance(record["entry_existed"], bool):
        raise ConfigConflict(
            f"the record for {name!r} has an entry_existed that is not a bool; "
            f"it decides whether uninstall restores an entry or deletes one, so "
            f"a value we cannot read is not a default")
    state = record.get("state")
    if state != expect_state:
        raise ConfigConflict(
            f"the record for {name!r} is marked {state!r}, not {expect_state!r}; "
            f"refusing to act on a transaction in a state we did not leave it in")
    return record


def resolve_artifact(*, package_root=None):
    """The artifact a wrapper must point at: this package's proxy entry point.

    Refuses when it is absent rather than returning a path that cannot run. On a
    tree without the proxy lane's `__main__.py` that means `install` refuses
    every time, which is the honest state and is C5 one level up from the
    argument check.
    """
    if package_root is None:
        package_root = pathlib.Path(__file__).resolve().parent
    entry = pathlib.Path(package_root) / "proxy" / "__main__.py"
    if not entry.is_file():
        raise ArtifactUnresolved(
            f"no proxy entry point at {entry}; this build cannot wire a route, "
            f"so refusing rather than writing a config that runs nothing"
        )
    return entry


def _could_execute(command) -> bool:
    """Is this EXACTLY the interpreter we wired (F2)?

    Decided WITHOUT the marker, because the marker is the thing being checked.

    Round 3 accepted any basename beginning with "python", which is a
    RESEMBLANCE test and not an identity one: a shim named `python-shim` that
    exits 0 and runs nothing satisfied it, so a wrapper pointing at that shim
    classified WRAPPED and the route was reported protected while the artifact
    never ran. `/usr/bin/true` was refused and `./python-shim` was not, and the
    only difference between them is a name.

    `install` writes `sys.executable` into BOTH the entry's command and the
    marker's command, so exact equality is what a route we created round-trips
    through. Anything else is a route we cannot vouch for, which classifies
    UNVERIFIED -- a refusal to vouch, not an accusation, and the caller decides
    what to do about it.

    BOUNDARY CHANGE, stated because it moves rows between two public answers:
    a wrapper whose command merely names a python used to be WRAPPED and is now
    UNVERIFIED. Nothing moves into or out of DIRECT, because DIRECT is decided
    earlier and only by the absence of the marker.
    """
    return isinstance(command, str) and command == sys.executable


def classify(entry, *, artifact):
    """DIRECT (no wrapper) · WRAPPED (this artifact, and the entry really runs
    it) · UNVERIFIED (a wrapper we cannot vouch for).

    Matching metadata is not enough. C6-ROUTE: with a correct path and digest in
    the marker, changing the command, changing the argv or emptying it still
    left round 1 calling the route WRAPPED. Classification is bound to what the
    entry executes.
    """
    if not isinstance(entry, dict):
        return "UNVERIFIED"
    meta = entry.get(MARKER)
    if not isinstance(meta, dict):
        return "DIRECT"
    try:
        actual = _digest_file(artifact)
    except OSError:
        return "UNVERIFIED"
    resolved = str(pathlib.Path(artifact).resolve())
    if meta.get("artifact") != resolved or meta.get("sha256") != actual:
        return "UNVERIFIED"
    # C6-COMMAND-BINDING. The marker is untrusted data in a file the user (or
    # anything else) can edit, so it cannot vouch for itself: setting BOTH the
    # entry's command and the marker's command to `/usr/bin/true` made them
    # agree while the artifact never ran. Agreement is necessary and not
    # sufficient; the command also has to be something that could execute the
    # artifact, judged without reading the marker.
    command = entry.get("command")
    if command != meta.get("command") or not _could_execute(command):
        return "UNVERIFIED"
    args = entry.get("args")
    if not isinstance(args, list) or args[:2] != [resolved, "--"]:
        return "UNVERIFIED"
    return "WRAPPED"


def install(config_path, name, *, artifact, home, argv=None):
    """Wrap one entry. Validates everything, then mutates recoverably.

    The whole transaction runs under one lock on the target, not just the
    write: round 6 closed the compare against the rename and round 7's
    `R6_OWNER_CHECK_UNLINK_GAP` moved the same race to the cleanup, where a
    second install completed between the check that the retained original was
    unclaimed and the unlink that removed it. Serialising one syscall at a time
    is how a race gets moved rather than closed.
    """
    with _locked_for(config_path, _lock_path(home, config_path)):
        return _install_locked(config_path, name, artifact=artifact, home=home,
                               argv=argv)


def _install_locked(config_path, name, *, artifact, home, argv=None):
    artifact = pathlib.Path(artifact)
    try:
        digest = _digest_file(artifact)
    except OSError as e:
        raise ArtifactUnresolved(
            f"no proxy entry point at {artifact}; refusing to write a config "
            f"that would look protected and run nothing"
        ) from e
    resolved = str(artifact.resolve())

    target = pathlib.Path(config_path)
    raw = _read_bytes(target)
    doc = _parse(raw, target)
    servers = _servers(doc, target)

    # Any marker at all stops us, verified or not (C2-REPEAT, C2-DRIFT).
    existing = servers.get(name)
    if isinstance(existing, dict) and MARKER in existing:
        if classify(existing, artifact=artifact) == "WRAPPED":
            raise ConfigConflict(
                f"{name!r} is already wrapped in {target}; nothing to do")
        raise ConfigConflict(
            f"{name!r} already carries a wrapper this build cannot verify; "
            f"refusing to nest another inside it")

    if name in servers:
        _validate_entry(existing, name, target)
        original_entry = json.loads(json.dumps(existing))
        entry_existed = True
    else:
        if argv is None:
            raise ConfigConflict(f"no MCP server named {name!r} in {target}")
        if not (isinstance(argv, (list, tuple)) and argv
                and all(isinstance(a, str) for a in argv)):
            raise ConfigIOError("the supplied argv is not a non-empty list of strings")
        original_entry = {"command": argv[0], "args": list(argv[1:])}
        entry_existed = False

    target_id = str(target.resolve())
    _, rec_path, pending_path, bytes_path = _records_dir(home, name)
    _refuse_symlinked_storage(name, rec_path, pending_path, bytes_path)

    # R4/R5-COLLISION and R4-IDENTITY-BEFORE-DIGEST. A completed record means an
    # install is OUTSTANDING, and its retained bytes are the only way back to
    # the state it captured. Overwriting it destroys that, which is what
    # happened when a config was edited back to unwrapped and installed again:
    # same path, different identity, prior recovery material gone.
    if rec_path.exists():
        prior = None
        try:
            prior = _read_record(rec_path, name, expect_state="complete")
        except ConfigConflict:
            pass
        belongs = prior.get("target_path") if prior else None
        raise ConfigConflict(
            f"{name!r} already has a completed install record"
            + (f" for {belongs}" if belongs else "")
            + "; uninstall it before installing again, so the bytes it retained "
              "are not the ones we throw away")

    # A pending journal is a transaction we left open (R-177-R3: recover or
    # refuse, never strand). It is safe to resume ONLY when the target is still
    # byte-for-byte what the journal captured, i.e. the crash happened before
    # the replace. Otherwise we cannot tell what is on disk and we refuse.
    if pending_path.exists():
        journal = _read_record(pending_path, name, expect_state="pending")
        if journal.get("target_path") != target_id:
            raise ConfigConflict(
                f"an open transaction for {name!r} describes "
                f"{journal.get('target_path')}, not {target}")
        if _digest_bytes(raw) != journal.get("file_sha_before"):
            raise ConfigConflict(
                f"an open transaction for {name!r} captured a different version "
                f"of {target}; uninstall to recover it before installing again")
        _discard(pending_path)

    # R4-OPTIONS: env, cwd and anything else the entry carries survive.
    wrapper = {k: v for k, v in original_entry.items() if k not in ("command", "args")}
    wrapper["command"] = sys.executable
    wrapper["args"] = [resolved, "--", original_entry["command"],
                       *(original_entry.get("args") or [])]
    wrapper[MARKER] = {"artifact": resolved, "sha256": digest,
                       "command": sys.executable}
    servers[name] = wrapper
    new_raw = (json.dumps(doc, indent=2) + "\n").encode("utf-8")

    record = {
        "original_entry": original_entry,
        "installed_entry": wrapper,
        "file_sha_before": _digest_bytes(raw),
        "file_sha_after": None,
        "original_bytes_path": str(bytes_path),
        "target_path": target_id,
        "entry_existed": entry_existed,
    }

    try:
        bytes_path.write_bytes(raw)
        retained_identity = _identity(bytes_path)
    except OSError as e:
        raise ConfigIOError(f"cannot retain the original bytes: {e}") from e
    try:
        pending_path.write_text(json.dumps({**record, "state": "pending"}, indent=2),
                                encoding="utf-8")
        journal_identity = _identity(pending_path)
    except OSError as e:
        # A half-written journal is worse than none: it is unparseable recovery
        # material that the next run would have to refuse. Remove both.
        _discard(pending_path, bytes_path)
        raise ConfigIOError(f"cannot write the pending record: {e}") from e

    try:
        _atomic_write(target, new_raw)
    except ConfigIOError:
        _discard(bytes_path, pending_path)
        raise

    # R7-CANCELLED-IN-FLIGHT (ASTRA round 6, `R6_INSTALL_RACES_UNINSTALL`). A
    # concurrent uninstall ran while we were inside the replace. It found our
    # PENDING journal, could not tell an interrupted transaction from a live
    # one, correctly concluded the target was still the original, and discarded
    # our journal and our retained bytes. Every step of that is defensible from
    # where it stood. What is not defensible is what we did next: we published
    # the wrapper and wrote a completed record pointing at retained bytes that
    # no longer exist, so the install looked successful and had no inverse.
    #
    # The transaction that cannot see the other one is the one that must check.
    # An install owns its own material from the moment it writes it, and at the
    # commit boundary it either still owns it or it was cancelled while in
    # flight. Cancelled means the target goes back and the caller is told, never
    # a wrapper with nothing behind it.
    wrapped_bytes, wrapped_identity = _read_bytes_and_identity(target)
    if not (_still_ours(bytes_path, retained_identity)
            and _still_ours(pending_path, journal_identity)):
        restored = True
        try:
            with _expect_unchanged(target, _digest_bytes(wrapped_bytes),
                                   wrapped_identity):
                _atomic_write(target, raw)
        except (ConfigIOError, ConfigConflict):
            restored = False
        _discard(rec_path)
        raise ConfigConflict(
            f"the open transaction installing {name!r} was cancelled by another "
            f"process while this one was writing {target}"
            + ("; the target was restored" if restored else
               f"; THE TARGET IS STILL WRAPPED and its retained original is "
               f"gone, so {target} must be reconciled by hand"))

    # C4-RECORD: completion is part of the transaction. If it fails, put the
    # target back rather than leaving a wrapped config with nothing to undo it.
    try:
        record["file_sha_after"] = _digest_bytes(wrapped_bytes)
        rec_path.write_text(json.dumps({**record, "state": "complete"}, indent=2),
                            encoding="utf-8")
    except (OSError, ConfigIOError) as e:
        rolled_back = True
        try:
            _atomic_write(target, raw)
        except ConfigIOError:
            rolled_back = False
        if rolled_back:
            # The target is the original again, so the journal and the retained
            # copy have nothing left to recover and would only confuse the next
            # run.
            _discard(bytes_path, pending_path, rec_path)
        else:
            # The target is STILL WRAPPED. The journal and the retained bytes
            # are now the only route back to the user's original, so deleting
            # them here would strand them permanently. Keep them and say so.
            _discard(rec_path)
        raise ConfigIOError(
            f"could not record the install: {e}"
            + ("; the target was restored" if rolled_back else
               f"; THE TARGET IS STILL WRAPPED. Its original is retained at "
               f"{bytes_path} and `sunglasses uninstall {name}` will restore it")
        ) from e

    _discard(pending_path)


def _retained_of(record, name, *, home):
    """The retained original, validated against the digest recorded at install
    AND against the only path we are willing to read it from (R5-RETAINED, F1).

    The digest check vouches for the BYTES and says nothing about WHERE they
    came from. `original_bytes_path` is a string in a file on disk, so a record
    naming an unrelated file made `uninstall` write that file's bytes into the
    user's config and then UNLINK it, returning byte_exact=True, because the
    bytes matched a digest the same record supplied. A record that supplies
    both halves of its own proof proves nothing.

    The check lives HERE and not in `uninstall` because
    `_recover_from_journal` reads the same field through this function. One
    choke point both callers pass through cannot be half-fixed; a check at one
    call site would have left the crash-recovery path holding the same hole,
    which is the shape that already cost this lane a round.

    The comparison is LEXICAL and deliberately not `resolve()`d on both sides:
    resolving the canonical path as well would follow a symlink planted at that
    name and both sides would agree on the attacker's target. So the name must
    match exactly, and a symlink AT that name is refused separately.
    """
    canonical = _record_paths(home, name)[3]
    retained_path = pathlib.Path(record["original_bytes_path"])
    if retained_path != canonical:
        raise ConfigConflict(
            f"the record for {name!r} keeps its retained original at "
            f"{retained_path}, not at {canonical}; refusing to read bytes "
            f"from, or delete, a file outside the install record's own "
            f"directory")
    if retained_path.is_symlink():
        raise ConfigConflict(
            f"the retained original for {name!r} at {retained_path} is a "
            f"symlink; refusing to restore from a name that points somewhere "
            f"else")
    try:
        retained = retained_path.read_bytes()
    except OSError as e:
        raise ConfigConflict(
            f"the retained original for {name!r} is missing: {e}") from e
    if _digest_bytes(retained) != record.get("file_sha_before"):
        raise ConfigConflict(
            f"the retained original for {name!r} does not match the digest "
            f"recorded at install; refusing to restore bytes we cannot vouch for")
    return retained_path, retained


def _installed_rendering(retained: bytes, name, journal):
    """The exact bytes `install` would have written for THIS journal.

    So that "is the target the state we left it in?" is answered by comparing
    bytes rather than by assuming. `install` renders with `indent=2` and a
    trailing newline from the parsed original, so the reconstruction is exact.
    Returns None when the retained original cannot produce a rendering, which
    is itself an answer: we cannot vouch for the current file.
    """
    try:
        doc = _strict_loads(retained, f"the retained original for {name!r}")
    except ConfigIOError:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("mcpServers"), dict):
        return None
    if not isinstance(journal.get("installed_entry"), dict):
        return None
    doc["mcpServers"][name] = journal["installed_entry"]
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def _recover_from_journal(target, name, pending_path, *, home):
    """Finish an interrupted install backwards, and ONLY from a state we left.

    R5-JOURNAL-CONFLICT (ASTRA round 4). This used to check the journal's target
    path and the retained digest and then copy the whole retained original over
    whatever was there. Both of those describe the JOURNAL; neither describes
    the file in front of us. So an unrelated edit made after the interrupted
    install was silently erased, and a conflicting edit was overwritten instead
    of refused, both with exit 0. A pending journal does not waive R5.

    There are exactly two states we are entitled to act on: the target is still
    the before-image, so the crash preceded the replace and there is nothing to
    write, or it is the wrapper we wrote, so the retained bytes are the way
    back. Anything else is somebody's edit and gets a typed refusal that keeps
    the journal, because destroying the recovery material is how a refusal
    becomes permanent.
    """
    journal = _read_record(pending_path, name, expect_state="pending")
    if journal.get("target_path") != str(target.resolve()):
        raise ConfigConflict(
            f"the open transaction for {name!r} describes "
            f"{journal.get('target_path')}, not {target}")
    retained_path, retained = _retained_of(journal, name, home=home)
    current, current_identity = _read_bytes_and_identity(target)

    if _digest_bytes(current) == _digest_bytes(retained):
        # The replace never landed. The target already IS the original.
        _discard(pending_path, retained_path)
        return UninstallResult(byte_exact=True)

    installed = _installed_rendering(retained, name, journal)
    if installed is not None and current == installed:
        # We are entitled to overwrite EXACTLY the wrapper we wrote, and the
        # digest travels into the writer so the entitlement is checked at the
        # rename and not here.
        with _expect_unchanged(target, _digest_bytes(installed),
                               current_identity):
            _atomic_write(target, retained)
        _discard(pending_path, retained_path)
        return UninstallResult(byte_exact=True)

    raise ConfigConflict(
        f"{target} is neither the bytes the open transaction for {name!r} "
        f"captured nor the wrapper it wrote, so it has been edited since; "
        f"restoring the retained original would throw that edit away. Refusing "
        f"and keeping the journal at {pending_path} so the recovery is still "
        f"available once the file is reconciled by hand")


def uninstall(config_path, name, *, home):
    """Restore. Byte-exact when the file has not moved, entry-only when it has,
    and a typed refusal whenever the state is not one we can vouch for.

    Under the same transaction lock as `install`, for the reason given there.
    """
    with _locked_for(config_path, _lock_path(home, config_path)):
        return _uninstall_locked(config_path, name, home=home)


def _uninstall_locked(config_path, name, *, home):
    target = pathlib.Path(config_path)
    _, rec_path, pending_path, _ = _record_paths(home, name)

    if not rec_path.exists():
        # C4-REPLACE-CRASH-RECOVERY. No completed record, but an open journal
        # means a transaction was interrupted, and if the replace had already
        # happened the user's config is wrapped with nothing claiming to own it.
        # The journal IS the recovery input, so uninstall consumes it rather
        # than telling the user there is nothing installed.
        if pending_path.exists():
            return _recover_from_journal(target, name, pending_path, home=home)
        raise ConfigConflict(f"no recorded install for {name!r}")
    try:
        record = _read_record(rec_path, name, expect_state="complete")
    except ConfigConflict:
        # R4-COMPLETE-PARTIAL. A completed record that cannot be READ is an
        # interrupted completion, not an authority. Before this, uninstall saw
        # the completed FILENAME, failed to parse it, and refused with exit 2
        # while the still-valid journal sat unread beside it: a stranded
        # transaction with its recovery material present on disk. The filename
        # no longer outranks the journal.
        if pending_path.exists():
            return _recover_from_journal(target, name, pending_path, home=home)
        raise

    recorded_target = record.get("target_path")
    if recorded_target != str(target.resolve()):
        raise ConfigConflict(
            f"the record for {name!r} describes {recorded_target}, not {target}")

    # R5-RETAINED: the retained bytes are validated before they are trusted,
    # and F1: so is the path they are read from and deleted at.
    retained_path, retained = _retained_of(record, name, home=home)

    current = _read_bytes(target)

    if _digest_bytes(current) == record.get("file_sha_after"):
        # C1: the retained BYTES, never a re-serialisation of the parsed
        # original. A re-render compares equal under json.loads and differs on
        # disk, so it would reformat a file we do not own.
        _atomic_write(target, retained)   # byte-exact restore
        _discard(rec_path, pending_path, retained_path)
        return UninstallResult(byte_exact=True)

    # The file moved under us. Put the entry back, or remove it if we created
    # it, and leave every unrelated property alone, collected by property
    # rather than by position (C3, R5-INVERSE).
    doc = _parse(current, target)
    servers = _servers(doc, target)
    if name not in servers:
        raise ConfigConflict(f"{name!r} is no longer in {target}")
    if servers[name] != record.get("installed_entry"):
        raise ConfigConflict(
            f"the {name!r} entry is not the one we installed; refusing to "
            f"overwrite a change we did not make")
    if record.get("entry_existed", True):
        servers[name] = record["original_entry"]
    else:
        del servers[name]
    _atomic_write(target, (json.dumps(doc, indent=2) + "\n").encode("utf-8"))
    _discard(rec_path, pending_path, retained_path)
    return UninstallResult(byte_exact=False)

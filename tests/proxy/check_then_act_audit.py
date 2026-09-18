"""Every filesystem mutation install.py makes on SHARED RECOVERY STATE, with
the guard that makes each one safe. Ruling R-177-R11 (d).

Shared recovery state is the records directory: records, journals, retained
originals, standby pairs, set-aside failed copies and take notes. Two processes
can touch all of it at once, so each site is either atomic by construction or
holds something that makes it so.

WHY THIS IS AN AST WALK AND NOT A GREP. Round 10's version inventoried rename
RECEIVERS by regular expression, so it exited 0 on a source with an added
function containing `taking.unlink()` and `held.rename(q)` -- the reviewer wrote
exactly that and it passed. A mutation is a mutation whatever it is called: this
walks every `Call` node, keys each site by its enclosing function and its own
source text, and fails on any site with no entry. Adding a mutating line to
install.py fails this until someone says why it is safe.

Run: python3 tests/proxy/check_then_act_audit.py
"""
import ast
import pathlib
import sys

SOURCE = (pathlib.Path(__file__).resolve().parents[2]
          / "sunglasses" / "install.py")

# Method calls that CHANGE the filesystem.
MUTATORS = {"rename", "replace", "unlink", "write_text", "write_bytes",
            "mkdir", "chmod", "link", "symlink_to", "touch", "fsync"}
# Module-level functions that do, when called as os.<name>.
OS_MUTATORS = {"replace", "rename", "unlink", "remove", "link", "symlink",
               "mkdir", "makedirs", "chmod", "fsync", "ftruncate", "write"}

# "<function>: <source text>" -> why it is safe.
INVENTORY = {
    # Read-only opens, listed rather than exempted: the audit now refuses to
    # guess at flags it cannot read, and `_O_NOFOLLOW` is a module constant it
    # cannot follow. Each is O_RDONLY and creates nothing; saying so here is
    # cheaper than teaching the walker to resolve constants, and it leaves the
    # claim where a reader can check it.
    "_read_bytes_and_identity: os.open(str(path), os.O_RDONLY)":
        "Read-only. Opens the target to take bytes and identity from one fd.",
    "_authorise_from_one_fd: os.open(str(failed), os.O_RDONLY | _O_NOFOLLOW)":
        "Read-only, no-follow. THE authority fd, held across the write it "
        "licenses.",
    "_open_set_aside: os.open(str(failed), os.O_RDONLY | _O_NOFOLLOW)":
        "Read-only, no-follow. The predicate's own open.",
    # Repeats. Each occurrence is its own site and answers for itself; the
    # reviewer's duplicate-site shape is exactly this, and a single entry
    # covering both was how it walked past round 11.
    "_forget_held: private.unlink() #1":
        "The discard when the held bytes ARE answered for, on a note we hold "
        "exclusively.",
    "_forget_held: private.unlink() #2":
        "The discard after a successful link put the note back; the private "
        "name is ours alone at that point.",
    "_atomic_write: os.unlink(tmp) #1":
        "Cleanup of our own temp on the _Changed path.",
    "_atomic_write: os.unlink(tmp) #2":
        "Cleanup of our own temp on the ConfigIOError path.",
    "_atomic_write: os.fsync(fh.fileno()) #1":
        "The re-derivation's rewrite of our own temp.",
    "_adopt_standby: record_path.rename(rec_path) #1":
        "Promotion of a record whose bytes did not validate, after the failed "
        "copy has been set aside.",
    "_discard: held.unlink() #1":
        "Dropping our own superseded copy when the canonical slot was refilled "
        "by whoever wrote the record beside it.",
    "_install_locked: spare_record.rename(rec_path) #1":
        "Promotion of the marked record when the standby bytes did not "
        "validate.",
    "_exclusive: open(str(lock_path), \"a+\")":
        "The lock file itself. Creating it is not a change to recovery state; "
        "what it protects is taken with flock immediately after.",
    "_claim_take_note: os.open(str(taking), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)":
        "THE atomic claim. O_EXCL is the whole mechanism: the creation is the "
        "question and the file system answers it once.",
    "_reclaim_one: held.rename(bytes_path)":
        "Only after the held bytes hash to what the note recorded, on a note "
        "that passed every part of its validation.",
    "_atomic_write: open(tmp, \"wb\")":
        "Our own temp file, before any rename makes it visible.",
    "_atomic_write: os.replace(tmp, str(p))":
        "Under `_exclusive`, with the re-read, the re-derivation and the "
        "comparison in the same critical section.",
    "_atomic_write: os.unlink(tmp)":
        "Our own temp file, never shared state.",
    "_atomic_write: os.chmod(tmp, mode)":
        "Our own temp file.",
    "_atomic_write: os.fsync(fh.fileno())":
        "Our own temp file.",
    "_exclusive: lock_path.parent.mkdir(parents=True, exist_ok=True)":
        "Idempotent, and the lock file itself is created by `open`.",
    "_claim_take_note: taking.unlink()":
        "Only after our own O_EXCL creation failed to be written; nobody else "
        "can hold that name at that moment.",
    "_claim_take_note: taking.write_text(intent, encoding=\"utf-8\")":
        "The content of a note THIS call created exclusively.",
    "_forget_take: taking.rename(private)":
        "ATOMIC. Forgetting takes the note out of the way first and reads it "
        "afterwards; the private name stays discoverable to `_reclaim_taken`.",
    "_forget_held: private.unlink()":
        "A note we hold exclusively, either ours or stale once the name is "
        "taken by a new owner.",
    "_forget_held: os.link(str(private), str(taking))":
        "ATOMIC on the destination NAME: EEXIST means a new owner published "
        "and its note stands.",
    "_set_aside_failed: standby_bytes.rename(kept)":
        "A copy that failed its digest, moved to a name nothing else claims.",
    "_adopt_standby: record_path.rename(rec_path)":
        "Adoption, record first; the bytes are findable by the canonical "
        "record's digest if this is where the process ends.",
    "_adopt_standby: standby_bytes.rename(bytes_path)":
        "Adoption, bytes second, after the pair has been validated against the "
        "live file.",
    "_adopt_standby: orphan.rename(bytes_path)":
        "Half-promoted pair, keyed on the digest the canonical record carries.",
    "_adopt_standby: record_path.write_text(json.dumps(\n                    {**claim, \"failed_bytes_name\": failed_name,\n                     \"failed_bytes_sha256\": failed_sha}, indent=2),\n                    encoding=\"utf-8\")":
        "A standby record we still hold privately, before it is promoted.",
    "_discard: q.unlink()":
        "Records and journals, removed by the transaction that owns them; "
        "retained bytes never take this branch.",
    "_discard: q.rename(held)":
        "ATOMIC. The take moves an inode; a loser renames nothing.",
    "_discard: held.unlink()":
        "Bytes this call took exclusively.",
    "_discard: held.rename(q)":
        "Putting back bytes we took when a record turned out to claim them, "
        "only while the canonical name is free.",
    "_install_locked: bytes_path.write_bytes(raw)":
        "The canonical retained copy, written before the wrapper exists.",
    "_install_locked: pending_path.write_text(json.dumps({**record, \"state\": \"pending\"}, indent=2),\n                                encoding=\"utf-8\")":
        "The journal, written before the wrapper exists.",
    "_install_locked: rec_path.write_text(json.dumps({**record, \"state\": \"complete\"}, indent=2),\n                            encoding=\"utf-8\")":
        "Completion, after the wrapper is published and ownership re-checked.",
    "_install_locked: spare_record.rename(rec_path)":
        "Promotion, record first; nothing is discarded until the canonical "
        "pair is read back from disk.",
    "_install_locked: spare_bytes.rename(bytes_path)":
        "Promotion, bytes second.",
    "_install_locked: spare_record.write_text(json.dumps(\n                        {**record, \"file_sha_after\": _digest_bytes(wrapped_bytes),\n                         \"original_bytes_path\": str(bytes_path),\n                         \"failed_bytes_name\": failed_name,\n                         \"failed_bytes_sha256\": failed_sha,\n                         \"state\": \"complete\"},\n                        indent=2), encoding=\"utf-8\")":
        "A standby record we still hold privately, before promotion.",
    "_install_locked.render_again: bytes_path.write_bytes(current)":
        "Re-derivation under the writer lock; the inverse is rewritten to "
        "describe the bytes actually being overwritten.",
    "_install_locked.render_again: pending_path.write_text(\n                json.dumps({**record, \"state\": \"pending\"}, indent=2),\n                encoding=\"utf-8\")":
        "Same, for the journal.",
    "_install_locked.stand_by: spare_bytes.write_bytes(original)":
        "The standby copy, written before the wrapper it is the inverse of.",
    "_install_locked.stand_by: spare_record.write_text(json.dumps(\n            {**record, \"file_sha_after\": _digest_bytes(published),\n             \"original_bytes_path\": str(bytes_path), \"state\": \"complete\"},\n            indent=2), encoding=\"utf-8\")":
        "Same, for its record.",
    "_uninstall_locked: canonical.rename(kept)":
        "Setting aside a copy that failed its digest; nothing claims that name.",
    "_records_dir: d.mkdir(parents=True, exist_ok=True)":
        "Idempotent creation of our own records directory.",
    "_records_dir: os.chmod(str(d), 0o700)":
        "Our own records directory, narrowed at creation.",
    # Round 14's two collectors. Both remove a NOTE and never held bytes, and
    # each answers for itself rather than sharing one entry.
    "_collect_discharged_notes: spent.unlink()":
        "A note whose held file is no longer there. Recovery put those bytes "
        "back at the canonical name, so the note answers for a file that does "
        "not exist and nothing can be recovered from it.",
    "_collect_stale_aliases: alias.unlink()":
        "A private alias of a note we are holding ourselves, left by a process "
        "that has ended. Our own alias names the same held file with the same "
        "digest and cannot be collected by anyone while we live, so the route "
        "back is never empty.",
    # Round 15's owner files. The lock inside one is what proves an incarnation
    # ended; these two sites are that file's disposal.
    "_release_owner_file: _owner_file(private).unlink()":
        "Our own lock file, removed only once the alias it answers for is "
        "gone. While the alias stays the file stays, or no later collector "
        "could prove its writer had ended.",
    "_collect_stale_aliases: _owner_file(alias).unlink()":
        "The lock file of an alias we have just collected, whose owner that "
        "lock itself proved dead.",
    # NOT A FILESYSTEM MUTATION AT ALL, and inventoried BECAUSE the walk cannot
    # prove that. `replace` is in MUTATORS for `os.replace` and `Path.replace`;
    # this is `str.replace` on a name, and an AST cannot type the receiver. The
    # audit's own rule is that whatever it cannot prove harmless gets an entry
    # rather than an exemption, so it gets one -- with a reason a reader checks
    # in a line -- instead of the code being contorted to dodge the walker.
    "_owner_file: private.name.replace(\".taking.\", \".forgetlock.\", 1)":
        "A string method building a name. It touches no filesystem; the walker "
        "cannot type the receiver, so this is listed rather than exempted.",
}


WRITE_MODES = set("wax+")
OPEN_FLAGS = {"O_CREAT", "O_EXCL", "O_WRONLY", "O_RDWR", "O_TRUNC", "O_APPEND"}


def _qualified(tree):
    """id(node) -> dotted function path, innermost last."""
    out = {}

    def walk(node, path):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                here = path + [child.name]
                for inner in ast.walk(child):
                    out[id(inner)] = ".".join(here)
                walk(child, here)
            else:
                walk(child, path)

    walk(tree, [])
    return out


def _os_names(tree):
    """Every name bound to the os module, however it was imported.

    R13-ALIASES (ASTRA round 12, `R12_AUDIT_NEW_SHAPES[os_alias]`). `import os
    as anything` gives the same syscalls a different label, and an audit that
    matches the label `os` sees none of them.
    """
    names = {"os"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "os":
                    names.add(a.asname or "os")
    return names


def _aliases(tree):
    """Names bound to mutating callables by an import, e.g. `from os import
    unlink`. Round 11 renamed one of these and the regular-expression audit did
    not notice; an alias is the same syscall with a different label."""
    bound = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in ("os", "shutil"):
            for a in node.names:
                if a.name in OS_MUTATORS or a.name in {"remove", "rmtree"}:
                    bound[a.asname or a.name] = a.name
    return bound


def _is_mutation(node, aliases, os_names):
    """Every shape that changes the filesystem, by AST rather than by name.

    UNKNOWN COUNTS AS MUTATING. Round 12 read the flags of `os.open` and the
    mode of `open` only when they were literals, so putting either in a
    variable hid the call. An audit that cannot prove a call is harmless has
    not proved anything, so anything it cannot read is inventoried.
    """
    f = node.func
    if isinstance(f, ast.Attribute):
        if isinstance(f.value, ast.Name) and f.value.id in os_names:
            if f.attr == "open":
                if len(node.args) < 2:
                    return False            # read-only by signature
                for arg in node.args[1:]:
                    if not isinstance(arg, (ast.BinOp, ast.Attribute,
                                            ast.Constant)):
                        return True         # flags we cannot read
                    for sub in ast.walk(arg):
                        if isinstance(sub, ast.Attribute) and sub.attr in OPEN_FLAGS:
                            return True
                        if isinstance(sub, ast.Name):
                            return True     # a variable in the flags
                return False
            return f.attr in OS_MUTATORS
        return f.attr in MUTATORS
    if isinstance(f, ast.Name):
        if f.id in aliases:
            return True
        if f.id == "open":
            if len(node.args) < 2 and not node.keywords:
                return False                # read-only by signature
            for arg in node.args[1:]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if set(arg.value) & WRITE_MODES:
                        return True
                else:
                    return True             # a mode we cannot read
            for kw in node.keywords:
                if kw.arg == "mode":
                    if isinstance(kw.value, ast.Constant):
                        if set(kw.value.value or "") & WRITE_MODES:
                            return True
                    else:
                        return True
            return False
    return False


def main():
    src = SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(src)
    # R13-SITE-IDENTITY (ASTRA round 12,
    # `R12_AUDIT_NEW_SHAPES[qualified_site_relocation]`). A site is named by its
    # FULL dotted path, not by the innermost function's bare name. Round 12's
    # version computed the path and then threw it away, keying on the bare name
    # instead: defining a nested helper called `_discard` anywhere in the file
    # gave its `q.unlink()` the key `_discard: q.unlink()`, which is the
    # module-level `_discard`'s inventory entry. The reviewer moved the real
    # site out and put an unaudited one in under that borrowed answer, and the
    # audit exited 0. A path cannot be borrowed: the same helper nested in
    # `review_extra` is `review_extra._discard` and has no entry.
    where = _qualified(tree)

    aliases = _aliases(tree)
    os_names = _os_names(tree)
    sites = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_mutation(node, aliases, os_names):
            continue
        text = ast.get_source_segment(src, node) or ""
        sites.append((node.lineno, where.get(id(node), "<module>"), text))

    # The key is (qualified function path, call text, which occurrence). A
    # nested helper has its own path so it cannot inherit a module-level
    # entry's answer, and two identical calls in one function are two sites
    # rather than one -- both shapes walked past round 11's version, which
    # keyed on the bare name.
    seen = {}
    keyed = []
    unlisted = []
    for lineno, func, text in sites:
        base = f"{func}: {text}"
        n = seen.get(base, 0)
        seen[base] = n + 1
        key = base if n == 0 else f"{base} #{n}"
        keyed.append((lineno, func, text, key))
        if key not in INVENTORY:
            unlisted.append((lineno, key))

    print(f"{SOURCE.name}: {len(sites)} filesystem mutations on shared "
          f"recovery state, {len(sites) - len(unlisted)} inventoried\n")
    # The listing marks each site by the SAME key the decision used. Round 12's
    # version recomputed a key without the occurrence suffix here, so the second
    # of two identical calls printed as inventoried while being counted
    # unaudited -- a readout that disagrees with the verdict it is printed under.
    for lineno, func, text, key in keyed:
        mark = "  " if key in INVENTORY else "!!"
        one_line = " ".join(text.split())
        print(f"{mark} {SOURCE.name}:{lineno:<5} {func}: {one_line[:70]}")
    if unlisted:
        print(f"\nUNAUDITED ({len(unlisted)}): every one of these changes the "
              f"filesystem and no entry says why it is safe")
        for lineno, key in unlisted:
            print(f"  {SOURCE.name}:{lineno} {' '.join(key.split())[:100]}")
        return 1
    # AND THE REVERSE. R14-AN-ANSWER-WITH-NO-QUESTION. The walk proves every
    # site has an entry and has never proved every entry has a site. Three
    # entries on `8349bb6` named call text that is nowhere in the file any
    # more; they had outlived their sites quietly, because nothing looked.
    #
    # A stale entry is a PRE-LOADED BORROWED ANSWER. The moment any function
    # acquires that name and that call text, an unaudited site is inventoried
    # the instant it is written -- which is round 12's relocation escape
    # arriving from the other direction, and removing the three instances
    # without this would leave the class open. The inventory is checked BOTH
    # ways now.
    stale = sorted(set(INVENTORY) - {key for _, _, _, key in keyed})
    if stale:
        print(f"\nSTALE ({len(stale)}): every one of these answers for a call "
              f"that is no longer in the file")
        for key in stale:
            print(f"  {' '.join(key.split())[:100]}")
        return 1
    print("\nevery filesystem mutation is inventoried, and every entry has a "
          "site")
    return 0


if __name__ == "__main__":
    sys.exit(main())

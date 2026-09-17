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
    "_claim_take_note: os.fsync(fh.fileno())":
        "Our own descriptor.",
    "_forget_take: taking.rename(private)":
        "ATOMIC. Forgetting takes the note out of the way first and reads it "
        "afterwards; the private name stays discoverable to `_reclaim_taken`.",
    "_forget_take: private.unlink()":
        "A note we hold exclusively, either ours or stale once the name is "
        "taken by a new owner.",
    "_forget_take: os.link(str(private), str(taking))":
        "ATOMIC on the destination NAME: EEXIST means a new owner published "
        "and its note stands.",
    "_reclaim_taken: held.rename(bytes_path)":
        "Only after the held bytes hash to what the note recorded.",
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
    "render_again: bytes_path.write_bytes(current)":
        "Re-derivation under the writer lock; the inverse is rewritten to "
        "describe the bytes actually being overwritten.",
    "render_again: pending_path.write_text(\n                json.dumps({**record, \"state\": \"pending\"}, indent=2),\n                encoding=\"utf-8\")":
        "Same, for the journal.",
    "stand_by: spare_bytes.write_bytes(original)":
        "The standby copy, written before the wrapper it is the inverse of.",
    "stand_by: spare_record.write_text(json.dumps(\n            {**record, \"file_sha_after\": _digest_bytes(published),\n             \"original_bytes_path\": str(bytes_path), \"state\": \"complete\"},\n            indent=2), encoding=\"utf-8\")":
        "Same, for its record.",
    "_uninstall_locked: canonical.rename(kept)":
        "Setting aside a copy that failed its digest; nothing claims that name.",
    "_refuse_symlinked_storage: p.parent.mkdir(parents=True, exist_ok=True)":
        "Idempotent creation of our own records directory.",
    "_records_dir: d.mkdir(parents=True, exist_ok=True)":
        "Idempotent creation of our own records directory.",
    "_records_dir: os.chmod(str(d), 0o700)":
        "Our own records directory, narrowed at creation.",
}


def main():
    src = SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(src)
    # Innermost function wins: a nested helper is its own site, and reporting
    # it under the enclosing function would let two different sites share a key.
    where = {}
    funcs = []

    def collect(node, depth):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.append((depth, child))
                collect(child, depth + 1)
            else:
                collect(child, depth)

    collect(tree, 0)
    for _, fn in sorted(funcs, key=lambda x: x[0]):
        for child in ast.walk(fn):
            where[id(child)] = fn.name

    sites = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        attr = node.func.attr
        is_os = (isinstance(node.func.value, ast.Name)
                 and node.func.value.id == "os" and attr in OS_MUTATORS)
        if attr not in MUTATORS and not is_os:
            continue
        text = ast.get_source_segment(src, node) or ""
        sites.append((node.lineno, where.get(id(node), "<module>"), text))

    unlisted = []
    for lineno, func, text in sites:
        key = f"{func}: {text}"
        if key not in INVENTORY:
            unlisted.append((lineno, key))

    print(f"{SOURCE.name}: {len(sites)} filesystem mutations on shared "
          f"recovery state, {len(sites) - len(unlisted)} inventoried\n")
    for lineno, func, text in sites:
        key = f"{func}: {text}"
        mark = "  " if key in INVENTORY else "!!"
        one_line = " ".join(text.split())
        print(f"{mark} {SOURCE.name}:{lineno:<5} {func}: {one_line[:70]}")
    if unlisted:
        print(f"\nUNAUDITED ({len(unlisted)}): every one of these changes the "
              f"filesystem and no entry says why it is safe")
        for lineno, key in unlisted:
            print(f"  {SOURCE.name}:{lineno} {' '.join(key.split())[:100]}")
        return 1
    print("\nevery filesystem mutation is inventoried")
    return 0


if __name__ == "__main__":
    sys.exit(main())

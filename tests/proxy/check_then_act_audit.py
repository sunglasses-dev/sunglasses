"""Every place install.py acts on SHARED RECOVERY STATE, and what makes each
one safe. Ruling R-177-R10 (d).

Shared recovery state is the records directory: records, journals, retained
originals, standby pairs and take notes. Two processes can touch all of it at
once, so every site here is either atomic by construction or holds something
that makes it so. A site with no entry is the defect this audit exists to find:
run it and it fails rather than printing a longer table.

Run: python3 warroom_check_then_act_audit.py
"""
import pathlib
import re
import sys

SOURCE = (pathlib.Path(__file__).resolve().parents[2]
          / "sunglasses" / "install.py")

# operation -> the guard that makes every occurrence of it safe
GUARDS = {
    "_claim_take_note": "ATOMIC. O_EXCL creation is the question and the answer.",
    "q.rename(held)": "ATOMIC. The take moves an inode; a loser renames nothing.",
    "taking.rename(private)": "ATOMIC. Forgetting takes the note out of the way "
                              "first, then reads it, then puts it back if it is "
                              "not ours.",
    "spare_record.rename(rec_path)": "ATOMIC pair, and discoverable between the "
                                     "two: `_adopt_standby` finds either half.",
    "spare_bytes.rename(bytes_path)": "Same pair; nothing is discarded until both "
                                      "are read back from disk.",
    "record_path.rename(rec_path)": "Adoption, under the same order as `_discard`: "
                                    "record first, bytes second.",
    "standby_bytes.rename(bytes_path)": "Adoption, second half; a process that "
                                        "ends between them leaves the orphan "
                                        "branch to find.",
    "orphan.rename(bytes_path)": "Adoption of a half-promoted pair, keyed on the "
                                 "digest the canonical record carries.",
    "held.rename(bytes_path)": "Reclaim, and only after the held bytes hash to "
                               "what the note recorded.",
    "canonical.rename(kept)": "Setting aside an unusable copy; nothing else "
                              "claims that name.",
    "private.rename(taking)": "Putting back a note that turned out to belong to "
                              "somebody else; we hold it exclusively until then.",
    "os.replace(tmp, str(p))": "Under `_exclusive`, with the re-read, the "
                               "re-derivation and the comparison.",
}

# read-then-act sites that are deliberately NOT atomic, each with why
ACCEPTED = {
    "_note_is_live": "A FAST PATH ONLY. Its answer can be stale; `_claim_take_note` "
                     "refuses regardless, so nothing is written or unlinked on the "
                     "strength of it.",
    "q.with_suffix('.json').exists()": "Asked AFTER the bytes are taken, about an "
                                       "inode we already hold.",
}


def main():
    src = SOURCE.read_text(encoding="utf-8")
    sites = []
    for line_no, line in enumerate(src.splitlines(), 1):
        text = line.strip()
        if text.startswith("#") or not text:
            continue
        for op in GUARDS:
            if op in text:
                sites.append((line_no, op, GUARDS[op]))
    unguarded = re.findall(r"^\s*(\w+)\.rename\(", src, re.M)
    known = {op.split(".")[0] for op in GUARDS}
    stray = sorted({n for n in unguarded if n not in known})

    print(f"{SOURCE.name}: {len(sites)} guarded sites on shared recovery state\n")
    for line_no, op, why in sites:
        print(f"  {SOURCE.name}:{line_no:<5} {op:<32} {why}")
    print("\nDeliberately not atomic:")
    for op, why in ACCEPTED.items():
        print(f"  {op:<34} {why}")
    if stray:
        print(f"\nUNAUDITED rename receivers: {stray}")
        return 1
    print("\nno unaudited rename on shared recovery state")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Every README in the real-world corpus has a MANIFEST.json row. Every row has its file.

sunglasses-dev__sunglasses.md sat in the corpus from 0.3.1 (#74) to 0.6.5 with no
row, so the manifest said 76 where the corpus held 77. Nothing noticed. The
manifest is where each file's source and fetch date live, so a file without a
row has no recorded provenance.
"""
import json
import pathlib

CORPUS = pathlib.Path(__file__).resolve().parent / "fp_real_world_corpus"


def test_manifest_rows_match_the_corpus_files():
    rows = set(json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8")))
    files = {p.name for p in CORPUS.glob("*.md")}
    assert rows == files, (
        f"MANIFEST.json has {len(rows)} rows for {len(files)} corpus files. "
        f"Files without a row: {sorted(files - rows)}. Rows without a file: {sorted(rows - files)}."
    )

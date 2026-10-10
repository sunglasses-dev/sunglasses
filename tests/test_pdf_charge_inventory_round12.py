"""Every place pdf.py dereferences, decodes or sizes something is named, with what pays for it.

The charge-before-touch rule was kept one call site at a time, so each review found the site
nobody had named. This test parses the module and fails on any dereference (`_resolve`,
`_deref`, `resolve`, `get_object`) or decode / size step (the decoder's stages, the sizing passes,
`get_data`, a bytes-to-text conversion) that is not in the table below, and on a table row whose
call is gone. A new site cannot go in without someone writing down what pays for it.

The same file runs in the document walk (A), the image walk (E) and the two together (C); a row
says in which of them it exists. Rows that say "fixed key" are a judgment the test cannot check:
whether the parent was charged is read by a person.

The same is done for conversions (a name to text, a value to a whole number, text to bytes, a join
of pieces): each is named with its kind. A "length gate" is a conversion that only runs inside a
test of the value's length, so it costs a bounded amount whatever the document holds, and the
test reads the source to find that test. A "fixed width" conversion is of a value whose size the
pattern or the type fixes. A "pass over paid bytes" is linear in bytes that were charged, or
reserved, before it ran, and the row says by what.
"""
import ast
from pathlib import Path

from sunglasses.extractors import pdf as pdf_module

_DEREF = {"_resolve", "_deref", "resolve", "get_object"}
_STEP = {"_decode_bounded", "_decode_stages", "_inflate", "_lzw_length", "_ascii85_length", "_bytes_text",
         "_decode_png_prediction", "get_data", "decode", "decompressobj", "decompress",
         "_charged_text"}

_CONVERT = {"str", "int", "encode", "from_bytes", "join", "sub", "bytes"}

DEREF, STEP, CONVERT = "deref", "step", "convert"
GATE, FIXED, PAID = "length gate", "fixed width", "pass over paid bytes"
A, E, C = "A", "E", "C"

# (kind, function, expression): (trees it exists in, what pays for it)
COVERED = {
    # --- the reader's own accessor, and the two helpers that wrap it
    # The accessor looks an object up. When the object sits in a compressed object stream the reader
    # inflates the whole stream, and that inflation is not the accessor's to charge: it is paid by
    # PDFExtractor._object_stream_fits, which the extractor installs on the reader before any check
    # runs (see _bounded_object_streams). The stream is decoded there once, charged, and handed to
    # the reader, so the reader's own decode never runs. tests/test_pdf_image_only_page_round16.py
    # checks this through extract(), with a spy on the reader's own Flate decode.
    (DEREF, "_deref", "obj.get_object"): ("AEC", "the accessor itself; an object in a compressed object stream is inflated by the reader, which _object_stream_fits has already done once, charged"),
    (DEREF, "_resolve", "obj.get_object"): ("EC", "the accessor itself; an object in a compressed object stream: see _deref"),
    (DEREF, "PDFExtractor._resolve", "obj.get_object"): ("A", "the accessor itself; an object in a compressed object stream: see _deref"),
    # --- the decoder: filter list and decode parameters go through _entries_of, which charges first
    (DEREF, "_filters_of", "n"): ("AEC", "an entry yielded by _entries_of, charged before it is yielded"),
    (DEREF, "_filters_of", "stream.get('/Filter')"): ("AEC", "fixed key of the stream being decoded"),
    (DEREF, "_predictor_of", "entry"): ("AEC", "an entry yielded by _entries_of, charged (a scalar is the stream's own)"),
    (DEREF, "_predictor_of", "params"): ("AEC", "fixed key of the stream being decoded"),
    (DEREF, "_predictor_of", "entry.get('/Predictor', predictor)"): ("AEC", "fixed key of a charged entry"),
    (DEREF, "_predictor_of", "entry.get('/Columns', columns)"): ("AEC", "fixed key of a charged entry"),
    (DEREF, "_predictor_of", "entry.get('/BitsPerComponent', bits)"): ("AEC", "fixed key of a charged entry"),
    # --- the decoder's stages
    (STEP, "_decode_stages", "_inflate"): ("AEC", "asked for room - spent, and room is taken down by every setup charge as it is made"),
    (STEP, "_inflate", "zlib.decompressobj"): ("AEC", "the stage is capped by the allowance the caller passes"),
    (STEP, "_inflate", "inflater.decompress"): ("AEC", "one call asks for no more than _INFLATE_STEP; a call that fails is charged that step"),
    (STEP, "_decode_stages", "pdf_filters.FlateDecode._decode_png_prediction"): ("AEC", "row length and output reserved against what is left before it runs"),
    (STEP, "_decode_stages", "_ascii85_length"): ("AEC", "the stream's own input is charged before the pass; a later stage's input is the stage before's output, already charged"),
    (STEP, "_decode_stages", "pdf_filters.ASCII85Decode.decode"): ("AEC", "after its size is charged and checked against the allowance"),
    (STEP, "_decode_stages", "_lzw_length"): ("AEC", "input charged before the pass, kept on the refused return; the pass stops at the allowance"),
    (STEP, "_decode_stages", "pdf_filters.LZWDecode.decode"): ("AEC", "after its size is charged and checked against the allowance"),
    # --- bytes to text
    (STEP, "_name", "data.decode"): ("EC", "a name drawn by content bytes that were charged when they were decoded"),
    (STEP, "PDFExtractor._bytes_text", "value.decode"): ("AC", "reached only through _charged_text or a stream's output, both charged first"),
    (STEP, "PDFExtractor._charged_text", "self._bytes_text"): ("AC", "after self._spend(len(raw))"),
    (STEP, "PDFExtractor._as_text", "self._charged_text"): ("AC", "charges the length before it converts"),
    (STEP, "PDFExtractor._decode_text", "data.decode"): ("AC", "data is the output of _bounded_stream_bytes, charged"),
    (STEP, "PDFExtractor._text_of", "data.decode"): ("AC", "data is the output of _bounded_stream_bytes, charged"),
    # --- the entry points of the decoder in each walk
    (STEP, "_decode_bounded", "_decode_stages"): ("AEC", "the same call under a wrapper that returns only what the decoder has not already put on the shared budget"),
    (STEP, "PDFExtractor._decode_stream", "_decode_bounded"): ("AC", "allowance is what is left; setup charged through _charge_visit, which returns what it charged; the result is charged on return, less what the decoder put on the budget itself before it resolved a parameter"),
    (STEP, "_ImageWalk._content", "_decode_bounded"): ("EC", "allowance is what is left; setup charged through _visit; the result is charged on return, less what the decoder put on the budget itself before it resolved a parameter"),
    # --- the image walk: _open charges a visit and then resolves
    (DEREF, "_ImageWalk._open", "ref"): ("EC", "charges its visit first"),
    (DEREF, "_ImageWalk.painted_images", "holder.get('/Resources')"): ("EC", "fixed key of the page, charged first in the method"),
    (DEREF, "_ImageWalk._find", "resources.get(kind)"): ("EC", "one of three fixed tables of a resource dictionary already opened"),
    (DEREF, "_ImageWalk._not_shown", "annot.get('/F')"): ("EC", "fixed key of an annotation opened by _open"),
    (DEREF, "_ImageWalk._appearances", "page.get('/Annots')"): ("EC", "fixed key of the page, charged first by painted_images"),
    (DEREF, "_ImageWalk._appearances", "annot.get('/AP')"): ("EC", "fixed key of an annotation opened by _open"),
    (DEREF, "_ImageWalk._appearances", "ref"): ("EC", "the /N of an annotation opened by _open (a fixed key)"),
    (DEREF, "_ImageWalk._appearances", "annot.get('/AS')"): ("EC", "fixed key of an annotation opened by _open"),
    (DEREF, "_ImageWalk._state", "state.get('/SMask')"): ("EC", "fixed key of a state opened by _open"),
    (DEREF, "_ImageWalk._state", "state.get('/Font')"): ("EC", "fixed key of a state opened by _open"),
    (DEREF, "_ImageWalk._type3", "font.get('/Resources')"): ("EC", "fixed key of a font opened by _open"),
    (DEREF, "_ImageWalk._type3.compute", "font.get('/CharProcs')"): ("EC", "fixed key of a font opened by _open"),
    (DEREF, "_ImageWalk._form", "form.get('/Resources')"): ("EC", "fixed key of a form opened by _open or read under its annotation's visit"),
    (DEREF, "_ImageWalk._content", "holder.get('/Contents')"): ("EC", "fixed key of the page, charged first by painted_images"),
    (DEREF, "_ImageWalk._content", "entry"): ("EC", "an array entry is opened by _open; any other is an object already resolved"),
    # --- the document walk: each array entry is charged (_spend / _entries_of) before it is resolved
    (DEREF, "PDFExtractor._as_text", "value"): ("AC", "a value of a charged field, annotation or tree pair; a string is charged by length before conversion"),
    (DEREF, "PDFExtractor._as_text", "item"): ("AC", "each entry charged by _spend(VISIT_COST) before it is looked at"),
    (DEREF, "PDFExtractor._text_of", "value"): ("AC", "a fixed key of a charged field, widget or parent"),
    (DEREF, "PDFExtractor._name_tree", "node"): ("AC", "the root is a fixed key; a kid is charged before it is queued"),
    (DEREF, "PDFExtractor._name_tree", "node.get('/Names')"): ("AC", "fixed key of a node already opened"),
    (DEREF, "PDFExtractor._name_tree", "node.get('/Kids')"): ("AC", "fixed key of a node already opened; each kid charged"),
    (DEREF, "PDFExtractor._scripts_in", "obj"): ("AC", "the first is a fixed key of a charged owner; later ones are charged before they are queued"),
    (DEREF, "PDFExtractor._scripts_in", "item"): ("AC", "charged by _spend(VISIT_COST) before it is resolved"),
    (DEREF, "PDFExtractor._extract_form_fields", "reader.trailer['/Root']"): ("AC", "once per document"),
    (DEREF, "PDFExtractor._extract_form_fields", "root.get('/AcroForm')"): ("AC", "fixed key of the root"),
    (DEREF, "PDFExtractor._extract_form_fields", "acroform.get('/Fields')"): ("AC", "fixed key of the form; each field charged"),
    (DEREF, "PDFExtractor._walk_fields", "ref"): ("AC", "counted and charged before it is resolved"),
    (DEREF, "PDFExtractor._walk_fields", "field['/Kids']"): ("AC", "fixed key of a charged field; an array walked under another parent is skipped whole"),
    (DEREF, "PDFExtractor._extract_document_scripts", "reader.trailer['/Root']"): ("AC", "once per document"),
    (DEREF, "PDFExtractor._extract_document_scripts", "root.get('/Names')"): ("AC", "fixed key of the root"),
    (DEREF, "PDFExtractor._extract_page_extras", "page['/Annots']"): ("AC", "fixed key of a page; the reader's page list is outside the budget"),
    (DEREF, "PDFExtractor._extract_page_extras", "annot"): ("AC", "charged by _spend(VISIT_COST) before the identity check and the resolve"),
    (DEREF, "PDFExtractor._parent_values", "node"): ("AC", "charged by _spend(VISIT_COST) first"),
    (DEREF, "PDFExtractor._associated_files", "files"): ("AC", "fixed key of a charged owner; each entry charged"),
    (DEREF, "PDFExtractor._extract_associated_files", "reader.trailer['/Root']"): ("AC", "once per document"),
    (DEREF, "PDFExtractor._extract_outlines", "reader.trailer['/Root']"): ("AC", "once per document"),
    (DEREF, "PDFExtractor._extract_outlines", "root['/Outlines']"): ("AC", "fixed key of the root"),
    (DEREF, "PDFExtractor._extract_outlines", "node"): ("AC", "charged by _spend(VISIT_COST) before it is resolved"),
    (DEREF, "PDFExtractor._read_filespec", "spec"): ("AC", "an /AF entry is charged by _associated_files; a tree pair by _name_tree"),
    (DEREF, "PDFExtractor._read_filespec", "spec.get('/EF')"): ("AC", "fixed key of a specification just resolved"),
    (DEREF, "PDFExtractor._read_filespec", "ef[k]"): ("AC", "one of the fixed alternatives of /EF, each distinct stream once, under the attachment cap"),
    (DEREF, "PDFExtractor._extract_attachments", "reader.trailer['/Root']"): ("AC", "once per document"),
    (DEREF, "PDFExtractor._extract_attachments", "root.get('/Names')"): ("AC", "fixed key of the root"),
    (DEREF, "PDFExtractor._object_stream_fits", "IndirectObject(stmnum, 0, reader).get_object"): ("AC", "the reader's own lookup of an object stream, which is then decoded once by _bounded_stream_bytes within the budget"),
    # --- outside the budget: not changed here, and said so
    (DEREF, "PDFExtractor._extract_annotations", "annot.get_object"): ("AEC", "legacy annotation text, unchanged from main: no visit charge and no array dedup (disclosed)"),
}


# (CONVERT, function, expression): (trees it exists in, kind, what bounds or pays for it)
CONVERTED = {
    (CONVERT, "_name_text", "str(name)"): ("AEC", GATE, "only inside `len(name) <= _MAX_NAME` and an instance test; a longer value, or one that is not a name, is never converted"),
    (CONVERT, "_whole", "int(value)"): ("AEC", GATE, "only after a text or byte value longer than _MAX_NUMBER has been refused; a number object is converted as it stands"),
    (CONVERT, "_lzw_length", "int.from_bytes"): ("AEC", FIXED, "three bytes at a code position, inside the sizing pass whose input was charged before it"),
    (CONVERT, "_inflate", "int.from_bytes"): ("AEC", FIXED, "two bytes of the gzip header extra length"),
    (CONVERT, "_inflate", "b''.join"): ("AEC", PAID, "the pieces are the inflater's output, each asked for within the allowance"),
    (CONVERT, "_decode_stages", "data.encode"): ("AEC", PAID, "only when a stage returned text; its length is at most the output reserved for that stage"),
    (CONVERT, "_name", "int"): ("EC", FIXED, "the group is the two hex digits of one #xx escape"),
    (CONVERT, "_name", "_NAME_ESCAPE.sub"): ("EC", PAID, "one pass over the name's raw bytes, which are bytes of a content stream already charged when it was decoded; the pattern matches a fixed three characters, so it does not backtrack"),
    (CONVERT, "_name", "bytes"): ("EC", FIXED, "one byte, built from the two hex digits of one #xx escape"),
    (CONVERT, "_ImageWalk._content", "b'\\n'.join"): ("EC", PAID, "the pieces are decoded states of the page, each charged before it is handled"),
    (CONVERT, "PDFExtractor._as_text", "' '.join"): ("AC", PAID, "the parts were each charged by _spend before they were collected"),
    (CONVERT, "PDFExtractor._charged_text", "str"): ("AC", PAID, "after self._spend(len(raw))"),
    (CONVERT, "PDFExtractor._charged_text", "text.encode"): ("AC", PAID, "text is the charged conversion above"),
}


def _tree():
    source = Path(pdf_module.__file__).read_text()
    if "class _ImageWalk" not in source:
        return A
    return E if "def _name_tree" not in source else C


def _sites():
    tree = ast.parse(Path(pdf_module.__file__).read_text())
    found = set()

    def visit(node, stack):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            stack = stack + [node.name]
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
            if name in _DEREF:
                found.add((DEREF, ".".join(stack), ast.unparse(node.args[0]) if node.args else ast.unparse(func)))
            elif name in _STEP:
                found.add((STEP, ".".join(stack), ast.unparse(func)))
        for child in ast.iter_child_nodes(node):
            visit(child, stack)

    visit(tree, [])
    return found


def _conversions():
    tree = ast.parse(Path(pdf_module.__file__).read_text())
    found = {}

    def visit(node, stack, tests):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            stack = stack + [node.name]
        if isinstance(node, ast.If):
            tests = tests + [node.test]
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
            if name in _CONVERT:
                where = ".".join(stack)
                if where:
                    text = ast.unparse(node)
                    # one row per kind of call: `int(x)` and `int(y)` in a function are one row
                    if name == "int" and isinstance(func, ast.Name):
                        text = "int(value)" if where == "_whole" else "int"
                    elif name == "str":
                        text = "str(name)" if where == "_name_text" else "str"
                    elif name == "from_bytes":
                        text = "int.from_bytes"
                    elif name == "join":
                        text = ast.unparse(func)
                    elif name == "encode" or name == "sub":
                        text = ast.unparse(func)
                    elif name == "bytes":
                        text = "bytes"
                    gated = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "len"
                                for t in tests for n in ast.walk(t))
                    found[(CONVERT, where, text)] = gated
        for child in ast.iter_child_nodes(node):
            visit(child, stack, tests)

    visit(tree, [], [])
    return found


def test_every_conversion_is_named_with_its_kind_and_what_bounds_it():
    here = _tree()
    expected = {key for key, (trees, _kind, _why) in CONVERTED.items() if here in trees}
    found = set(_conversions())
    assert found - expected == set(), f"a conversion nobody has said what bounds: {sorted(found - expected)}"
    assert expected - found == set(), f"a named conversion that is gone: {sorted(expected - found)}"


def test_a_conversion_called_a_length_gate_runs_only_inside_a_test_of_a_length():
    here = _tree()
    found = _conversions()
    gates = [key for key, (trees, kind, _why) in CONVERTED.items() if here in trees and kind == GATE]
    assert gates, "no length gate is named"
    for key in gates:
        assert found[key], f"{key} is called a length gate but is not inside a test that reads a length"


def test_a_conversion_not_called_a_length_gate_is_not_passed_off_as_one():
    # the other way: a row that says GATE must be one, and the rows that do not say it are not
    # relied on for a bound by length, so each of them names what bounds it
    for key, (trees, kind, why) in CONVERTED.items():
        assert kind in (GATE, FIXED, PAID) and why.strip(), key


def test_every_dereference_decode_and_size_step_is_named_with_what_pays_for_it():
    here = _tree()
    expected = {key for key, (trees, _why) in COVERED.items() if here in trees}
    found = _sites()
    assert found - expected == set(), f"a step nobody has said what pays for: {sorted(found - expected)}"
    assert expected - found == set(), f"a named step that is gone: {sorted(expected - found)}"


def test_every_row_says_what_pays():
    for key, (trees, why) in COVERED.items():
        assert trees and set(trees) <= {A, E, C} and why.strip(), key

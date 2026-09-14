import io
import json
import subprocess
import pytest
from probe_support import ROOT, ENV, dump, case, digest
import batch
import grade
from proxy import wiretap
from proxy import passthrough
from test_round4 import grader_baseline
OUT = ROOT / 'evidence/round5'

@pytest.mark.parametrize('tag', ['W01', 'W02', 'W03', 'W04'])
def test_wiretap_configured_bytes(tag, tmp_path):
    raw = {
        'W01': json.dumps({'id': 1, 'value': [1, 2]}).encode() + b'\n',
        'W02': bytes(range(256)) + b'\n',
        'W03': b'\n' * 3 + bytes([123, 125, 13, 10, 10]),
        'W04': bytes([97]) * 131073 + bytes([0, 255]),
    }[tag]
    config = batch.mcp_config(tmp_path, ['/bin/cat'], route='proxy_strict',
                              engine_root=ROOT / 'engine', deadline_ms=2000)
    server = json.loads(config.read_text())['mcpServers']['direct']
    result = subprocess.run([server['command'], *server['args']], input=raw,
                            capture_output=True, timeout=20, env=ENV)
    folder = OUT / tag
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'input.bin').write_bytes(raw)
    (folder / 'output.bin').write_bytes(result.stdout)
    (folder / 'stderr.bin').write_bytes(result.stderr)
    captures = {}
    for name in [batch.DIRECT_INGRESS, batch.DIRECT_EGRESS]:
        path = tmp_path / name
        captures[name] = path.read_bytes() if path.exists() else None
        if captures[name] is not None:
            (folder / name).write_bytes(captures[name])
    dump(folder / 'result.json', dict(exit=result.returncode, input_bytes=len(raw),
         output_bytes=len(result.stdout), input_sha256=digest(raw),
         output_sha256=digest(result.stdout),
         captures_equal={k: v == raw for k, v in captures.items()}))
    assert result.returncode == 0
    assert result.stdout == raw
    assert all(v == raw for v in captures.values())

def test_wiretap_does_not_parse(tmp_path, monkeypatch):
    raw = json.dumps({'id': 2, 'value': 3}).encode() + b'\n'
    calls = []
    original = json.loads
    def observe(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    class Output(io.BytesIO):
        def close(self): pass
    monkeypatch.setattr(json, 'loads', observe)
    output = Output()
    capture = tmp_path / 'capture.bin'
    wiretap._pump(io.BytesIO(raw), output, capture)
    dump(OUT / 'parse.json', dict(parse_calls=len(calls), output_equal=output.getvalue()==raw,
                                 capture_equal=capture.read_bytes()==raw))
    assert calls == []
    assert output.getvalue() == capture.read_bytes() == raw

@pytest.mark.parametrize('tag', ['E24', 'E25'])
def test_r7_endpoint_evidence_variants(tag, monkeypatch):
    directory = OUT / tag
    row, settled, payload, exp, write, baseline = grader_baseline(directory, monkeypatch)
    if tag == 'E24':
        for field in grade.ENDPOINT_FIELDS:
            row['destination'].pop(field)
    else:
        row['destination']['endpoint_as_declared'] = False
    write()
    result = grade.grade_row(directory)[1]
    dump(directory / 'result.json', dict(id=tag, scenario_id=row['scenario_id'],
         baseline=baseline, result=result, layer='destination',
         survived=result['destination']=='PASS'))
    assert result['destination'] != 'PASS'

def test_r7_two_reference_measurements():
    results = {}
    for number in [2, 4]:
        entry, folder, scenario, variant = case(number)
        message = json.loads((folder / variant['upstream_output']).read_bytes().splitlines()[0])
        declared = len((folder / variant['payload']).read_bytes())
        extracted = len('\n'.join(v for _, v in passthrough.inspection_input(message, 'result')).encode())
        reference = grade._reference_content_bytes({'scenario_id':entry['id'], 'variant':variant['name']})
        results[entry['id']] = dict(declared=declared, extracted=extracted, reference=reference)
    dump(OUT / 'references.json', results)
    assert results['G2-02'] == dict(declared=147, extracted=147, reference=147)
    assert results['G2-04'] == dict(declared=21, extracted=83, reference=None)

def test_native_direct_independent_captures(monkeypatch):
    import ast
    import test_round3
    from pathlib import Path
    text = (ROOT / 'test_round3.py').read_text()
    node = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef)
                and n.name == 'test_r1_actual_g2_12_direct_route_is_gradeable')
    class CaptureNames(ast.NodeTransformer):
        count = 0
        def visit_Constant(self, n):
            if n.value in (batch.DIRECT_INGRESS, batch.DIRECT_EGRESS):
                self.count += 1
                return ast.copy_location(ast.Constant('exam.' + n.value), n)
            return n
    change = CaptureNames()
    node = change.visit(node)
    assert change.count == 2
    module = ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[]))
    folder = OUT / 'native_captures'
    folder.mkdir(parents=True, exist_ok=True)
    namespace = dict(test_round3.__dict__, OUT=folder)
    exec(compile(module, str(ROOT / 'test_round3.py'), 'exec'), namespace)
    namespace[node.name](monkeypatch)
    rows = []
    for name in (batch.DIRECT_INGRESS, batch.DIRECT_EGRESS):
        paths = list(folder.rglob('exam.' + name))
        assert len(paths) == 1
        independent = paths[0].read_bytes()
        producer = paths[0].with_name(name).read_bytes()
        rows.append(dict(path=str(paths[0].with_name(name)), bytes=len(producer),
                         equal=producer==independent, sha256=digest(producer)))
    dump(folder / 'capture_equality.json', rows)
    assert all(r['equal'] for r in rows)

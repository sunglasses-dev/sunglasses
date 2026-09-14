import ast
import copy
import json
from pathlib import Path
import pytest
from probe_support import *
import batch
import grade
from destination.sink import Destination
from proxy import passthrough as proxy
OUT = ROOT / 'evidence/round4'
OUT.mkdir(parents=True, exist_ok=True)

def grader_baseline(directory, monkeypatch):
    entry, folder, scenario, variant = case(2)
    payload = (folder / variant['payload']).read_bytes()
    exp = grade.expectation(entry['id'], variant['name'], 'proxy_strict')
    row = dict(scenario_id=entry['id'], variant=variant['name'], route='proxy_strict',
               fs_tool_invoked=True, stimulus={'stimulus_exact': True}, session_id='local',
               destination=dict(listened=True, count=0, observation_complete=True,
                                declared_port=18762, bound_port=18762, endpoint_as_declared=True))
    settled = dict(kind='SETTLED', forwarded=True, reason=exp['policy']['reason_code'],
                   detector_status=exp['detector']['status'], inspection_complete=True,
                   detector={'rule_ids': []}, inspected_utf8_bytes=len(payload),
                   observed_content_bytes=len(payload))
    transcript = directory / 'transcript.jsonl'
    directory.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(grade, 'transcript_of', lambda *args: transcript)
    def write():
        dump(directory / 'row.json', row)
        (directory / 'proxy.receipts.jsonl').write_text(json.dumps(settled) + '\n')
        transcript.write_text(json.dumps({'message': {'content': [dict(type='tool_result',
                               tool_use_id='local', content=payload.decode())]}}) + '\n')
    write()
    baseline = grade.grade_row(directory)[1]
    dump(directory / 'baseline.json', baseline)
    assert set(baseline.values()) == {'PASS'}, 'BASELINE_NOT_GREEN'
    return row, settled, payload, exp, write, baseline

@pytest.mark.parametrize('tag', ['E18','E19','E20','E21','E22','E23'])
def test_r7_binding_variants(tag, monkeypatch):
    directory = OUT / tag
    row, settled, payload, exp, write, baseline = grader_baseline(directory, monkeypatch)
    layer = 'detector'
    if tag == 'E18':
        settled['inspected_utf8_bytes'] = settled['observed_content_bytes'] = 1
    elif tag == 'E19':
        settled['inspected_utf8_bytes'] = settled['observed_content_bytes'] = len(payload) + 1
    elif tag == 'E20':
        row['destination'].pop('endpoint_as_declared')
        layer = 'destination'
    elif tag == 'E21':
        row['destination']['bound_port'] += 1
        layer = 'destination'
    elif tag == 'E22':
        row['destination']['declared_port'] = row['destination']['bound_port'] = 43111
        layer = 'destination'
    elif tag == 'E23':
        row['destination'].pop('declared_port')
        row['destination'].pop('bound_port')
        layer = 'destination'
    write()
    result = grade.grade_row(directory)[1]
    dump(directory / 'result.json', dict(id=tag, scenario_id=row['scenario_id'], baseline=baseline,
                                       result=result, layer=layer, survived=result[layer]=='PASS'))
    assert result[layer] != 'PASS', 'R7_BINDING_SURVIVED'

def test_r7_unknown_decision_refused(monkeypatch):
    directory = OUT / 'unknown_decision'
    row, settled, payload, exp, write, baseline = grader_baseline(directory, monkeypatch)
    changed = copy.deepcopy(exp)
    changed['policy']['decision'] = 'UNRECOGNIZED_DECISION'
    monkeypatch.setattr(grade, 'expectation', lambda *args: changed)
    result = grade.grade_row(directory)[1]
    dump(directory / 'result.json', result)
    assert result['policy'] == 'INVALID_UNKNOWN_POLICY_DECISION'

def test_r5_releases_declared_endpoint_after_calibration(tmp_path):
    receipts = []
    for number in range(6):
        sink = Destination(drop_dir=tmp_path / str(number))
        try:
            sink.start()
            assert sink.bound_port == sink.declared_port == 18762
            sink.calibrate('before')
            sink.collect_drops()
            sink.calibrate('after')
            receipt = sink.receipt()
            assert receipt['observation_complete'] is True
            assert sink._server is None
            assert sink._thread is None
            receipts.append(receipt)
        finally:
            sink.stop()
    dump(OUT / 'r5_lifecycle.json', receipts)

def test_r1_direct_prompt_uses_declared_route(monkeypatch):
    entry, folder, scenario, variant = case(12)
    captured = {}
    def local(run_dir, prompt, config, *, dry_run, allowed):
        request = json.loads((run_dir / 'request.json').read_text())
        expected = 'mcp__direct__' + request['params']['name']
        captured.update(prompt_has_declared_tool=expected in prompt,
                        allowed_has_declared_tool=expected in allowed.split(','))
        return None, 'EXAM_LOCAL_STOP'
    monkeypatch.setattr(batch, 'call_claude', local)
    batch.run_one(entry, variant, outdir=OUT / 'prompt', route='proxy_strict',
                  engine_root=ROOT/'engine', upstream_argv=[sys.executable, str(ROOT/'upstream_driver.py')],
                  ledger=None, dry_run=True, call_no=0)
    dump(OUT/'r1_prompt.json', captured)
    assert captured['prompt_has_declared_tool'] and captured['allowed_has_declared_tool']

def test_r1_missing_direct_capture_does_not_attest(tmp_path):
    variant = case(12)[3]
    observed, attester = batch.route_call(tmp_path, 'proxy_strict', None, variant)
    dump(OUT/'r1_absent_capture.json', dict(observed=observed, attester=attester))
    assert observed is None
    assert attester is None, 'R1_ATTESTER_WITHOUT_CAPTURE'

def test_r1_configured_direct_route_produces_own_capture(monkeypatch):
    import test_round3
    text = (ROOT / 'test_round3.py').read_text()
    tree = ast.parse(text)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                and n.name == 'test_r1_actual_g2_12_direct_route_is_gradeable')
    class IndependentCapture(ast.NodeTransformer):
        count = 0
        def visit_Constant(self, value):
            if value.value == 'native.ingress.jsonl':
                self.count += 1
                return ast.copy_location(ast.Constant('exam.independent.ingress.jsonl'), value)
            return value
    transform = IndependentCapture()
    node = transform.visit(node)
    assert transform.count == 1
    module = ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[]))
    namespace = dict(test_round3.__dict__, OUT=OUT / 'configured_direct')
    namespace['OUT'].mkdir(parents=True, exist_ok=True)
    exec(compile(module, str(ROOT/'test_round3.py'), 'exec'), namespace)
    namespace[node.name](monkeypatch)

def test_r5_each_calibration_must_bind_declared_endpoint(tmp_path, monkeypatch):
    from destination import sink as sm
    real = sm.http.server.ThreadingHTTPServer
    attempts = []
    def bind(address, handler):
        attempts.append(address[1])
        if len(attempts) == 1 and address[1] == 18762:
            raise OSError('EXAM_INITIAL_BIND_FAILURE')
        return real(address, handler)
    monkeypatch.setattr(sm.http.server, 'ThreadingHTTPServer', bind)
    sink = Destination(drop_dir=tmp_path/'drop')
    try:
        sink.calibrate('before')
        sink.collect_drops()
        sink.calibrate('after')
        receipt = sink.receipt()
    finally:
        sink.stop()
    dump(OUT/'r5_endpoint_changes_between_calibrations.json', dict(attempts=attempts, receipt=receipt))
    http = [c for c in receipt['calibrations'] if c['transport'] == 'http']
    assert [c['endpoint_as_declared'] for c in http] == [False, True]
    assert receipt['observation_complete'] is False, 'R5_WRONG_BEFORE_ENDPOINT_ACCEPTED'

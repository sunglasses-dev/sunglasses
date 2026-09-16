"""RC10, vendored at the #178 round-2 rebase.

ASTRA's original named control for RC10 was scripts/test_closed_admission_control.py
in a review directory, and it was absent from this archive -- counted as green in
prior rounds on the strength of a run nobody here could repeat. Bytes recovered
from the round transcript that created it, unchanged.

It is the killing control for mutant P10, which survived every other row.
"""
from sunglasses.proxy import pump


def test_RC10_refused_readmission_preserves_the_settled_answer():
    s = pump.Session()
    assert s.admit_request(17, method='ping', origin='client')
    list(s.read_upstream(b''))
    answer = s.answer_for(17, origin='client')
    assert answer.reason == 'MALFORMED_UPSTREAM'
    assert not s.admit_request(17, method='ping', origin='client')
    assert s.answer_for(17, origin='client') == answer

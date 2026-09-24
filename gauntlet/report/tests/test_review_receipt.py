"""A review is RECORDED, never typed: `review_state: reviewed` needs a receipt.

T9 row 2026-09-23 (the capability map goes to ASTRA tonight): before this, the
only thing between an unreviewed map and a published ceiling was a string. Two
test fixtures set it by hand and `test_a_reviewed_map_still_loads` asserted that
hand-setting it WORKED, which is the forgery this row refuses.

Now `review.record()` writes a receipt bound to the map's CONTENT (every field
except the two review fields) and to a committed copy of the verdict text, and
`load_map` accepts `reviewed` only with a receipt that verifies. The receipt
does not authenticate the reviewer; it makes a review a hash-bound, verdict-
carrying artifact in git that a reader can check, and makes a typed
`reviewed` fail.
"""
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import classify  # noqa: E402
import review    # noqa: E402

GO_TEXT = "**GO — no blocker.** Test fixture verdict, not a real review.\n"
NOGO_TEXT = "**NO GO — one blocker:** test fixture.\n"


def _map_copy(tmp_path, **changes):
    data = json.loads(pathlib.Path(classify.__file__).with_name("capability_map.json").read_text())
    data.pop("review_receipt", None)
    data["review_state"] = "unreviewed"
    data.update(changes)
    p = tmp_path / "capability_map.json"
    p.write_text(json.dumps(data, indent=1))
    return p


def test_a_forged_review_state_with_no_receipt_is_refused(tmp_path):
    p = _map_copy(tmp_path, review_state="reviewed")
    with pytest.raises(classify.MapInvalid) as e:
        classify.load_map(p)
    assert "receipt" in str(e.value)


def test_a_recorded_go_loads_the_control(tmp_path):
    p = _map_copy(tmp_path)
    review.record(p, GO_TEXT, verdict="GO", reviewer="TEST-FIXTURE", round_id="t1")
    data = classify.load_map(p)
    assert data["review_state"] == "reviewed" and data["review_receipt"]


def test_a_map_changed_after_its_review_is_refused(tmp_path):
    p = _map_copy(tmp_path)
    review.record(p, GO_TEXT, verdict="GO", reviewer="TEST-FIXTURE", round_id="t1")
    data = json.loads(p.read_text())
    data["classified"]["answer_relist"]["evidence"] += " (edited after review)"
    p.write_text(json.dumps(data, indent=1))
    with pytest.raises(classify.MapInvalid) as e:
        classify.load_map(p)
    assert "content" in str(e.value)


def test_a_recorded_no_go_is_refused(tmp_path):
    """Recorded honestly, a NO GO leaves the map 'rejected', refused at the state."""
    p = _map_copy(tmp_path)
    review.record(p, NOGO_TEXT, verdict="NO GO", reviewer="TEST-FIXTURE", round_id="t1")
    assert json.loads(p.read_text())["review_state"] == "rejected"
    with pytest.raises(classify.MapInvalid):
        classify.load_map(p)


def test_reviewed_typed_over_a_no_go_receipt_is_refused(tmp_path):
    """The forgery that keeps the receipt: the state says reviewed, the receipt says NO GO."""
    p = _map_copy(tmp_path)
    review.record(p, NOGO_TEXT, verdict="NO GO", reviewer="TEST-FIXTURE", round_id="t1")
    data = json.loads(p.read_text()); data["review_state"] = "reviewed"
    p.write_text(json.dumps(data, indent=1))
    with pytest.raises(classify.MapInvalid) as e:
        classify.load_map(p)
    assert "NO GO" in str(e.value)


def test_a_tampered_verdict_is_refused(tmp_path):
    p = _map_copy(tmp_path)
    review.record(p, GO_TEXT, verdict="GO", reviewer="TEST-FIXTURE", round_id="t1")
    receipt = json.loads((p.parent / json.loads(p.read_text())["review_receipt"]).read_text())
    (p.parent / receipt["verdict_file"]).write_text("**GO** (rewritten)\n")
    with pytest.raises(classify.MapInvalid) as e:
        classify.load_map(p)
    assert "verdict" in str(e.value)


def test_a_verdict_that_does_not_say_what_the_receipt_claims_is_refused(tmp_path):
    p = _map_copy(tmp_path)
    with pytest.raises(review.ReviewInvalid):
        review.record(p, NOGO_TEXT, verdict="GO", reviewer="TEST-FIXTURE", round_id="t1")


def test_the_real_map_in_the_tree_is_not_reviewed_by_this_suite():
    """Nothing here may touch the shipped map."""
    # The FILE beside classify.py, not classify.MAP_PATH: the session conftest
    # points MAP_PATH at its reviewed copy.
    real = pathlib.Path(classify.__file__).with_name("capability_map.json")
    data = json.loads(real.read_text())
    assert data.get("review_state") == "unreviewed" and "review_receipt" not in data

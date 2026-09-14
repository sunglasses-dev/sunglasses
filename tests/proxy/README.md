# `tests/proxy/`

`test_independent.py` is ASTRA's file, vendored UNCHANGED from the PR #164
review of f43781b. Its sha256 is the one in that review's `SHA256SUMS`.

It is here as an acceptance set, not as a starting point. Editing it to make it
pass would destroy the only property that makes it worth having, which is that
it was written by somebody who did not write the code and did not know which
assertions the code would happen to satisfy. Seven mutations survived my own 47
tests and none survived this file.

If a check here is wrong, it is resolved with ASTRA and a new file is vendored.
It is not edited in place.

`ROOT` in that file points at `/private/tmp/PR164_REVIEW_f43781b_2026-09-13`,
which is the review's own fixture tree. The durable copy lives in
`Desktop/SUNGLASSES_ASTRA_REVIEW_2026-09-04/PR164_REVIEW_f43781b_2026-09-13/fixtures`.

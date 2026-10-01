# Witnesses

Each file here is the record of one executed run. A `*.json` summary sits beside the `*.receipts.jsonl` event stream the proxy wrote during that run.

Absolute paths from the machine that ran them are replaced by `<FIXTURE_ROOT>` and `<REPO_ROOT>`. The `upstream_argv_sha256` and `scanner_argv_sha256` values are kept exactly as recorded. They were computed over the original argv before the path scrub, so they will not match a hash of the argv text shown here. That is deliberate. The hash states what actually ran, and recomputing it over placeholder text would claim a run that never happened.

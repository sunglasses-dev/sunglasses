# The install/uninstall transaction

> **What `install` does today, measured rather than remembered.** With an
> `.mcp.json` present it rewrites the named entry to launch through the proxy in
> its module form and exits 0; with no `.mcp.json` at the target path it refuses
> and exits 2, naming the path. This page said the commands ship INERT and that
> `install` "refuses and exits 2 on every invocation", which was true before
> #195 and #201 merged and has not been true since.
>
> **Wiring is not approval and neither is protection.** Once wired, every call
> is still withheld with `APPROVAL_REQUIRED` until a person approves the
> server's tool snapshot at an interactive terminal. Source:
> `warroom/PROXY_ENFORCEMENT_PROBE_2026-09-21.md`.

Every claim below names the control that proves it. Where no control is named,
no claim is made.

## What it does

`sunglasses install <name>` rewrites one entry in an MCP config so that the
named server launches through Sunglasses instead of directly, and records enough
on disk to put it back exactly. `sunglasses uninstall <name>` puts it back.

Both are also importable: `sunglasses.install.install(config_path, name,
artifact=..., home=...)` and `.uninstall(config_path, name, home=...)`.

### Where the state lives

One tree, and it is the proxy's:

| what | where |
|---|---|
| install records, retained original bytes, writer locks | `~/.sunglasses/proxy/installs`, `~/.sunglasses/proxy/locks` |
| tool snapshots the proxy captures | `~/.sunglasses/proxy/captures` |
| approvals recorded by `proxy approve` | `~/.sunglasses/proxy/approvals` |
| scanner receipts, policy, pins | `$SUNGLASSES_HOME` or `~/.sunglasses` |

`serve.state_root()` decides the first three, and the CLI derives install's root
from it through `serve.install_records_home()` rather than choosing a matching
path of its own. **`$SUNGLASSES_HOME` does not reach the proxy lane.** It
relocates scanner state, which is what it is for; a variable that also moved the
approval store would be a switch anything in the process tree could flip, and
approvals read from a directory an attacker controls are approvals an attacker
writes. For the same reason `install` has no `--state-root`: a path chosen once
at config-write time is the same hole one layer up. `proxy approve --state-root`
remains the explicit, per-invocation override.

Until 2026-09-20 install used `$SUNGLASSES_HOME` while the proxy used
`Path.home()`, so with the variable set the record and the capture landed in
different trees. That is the surviving half of #204, where `proxy approve`
defaulted to the current directory and refused with a true statement about the
wrong place.

| | |
|---|---|
| `install <name>` | wraps the entry · `--config` · trailing `argv` after `--` when the entry does not exist yet |
| `uninstall <name>` | restores it · `--config` |

## What it wraps, and what it refuses to wrap

It wraps exactly the named entry and leaves the rest of the file alone
(`test_install_wraps_the_named_entry`,
`test_install_leaves_unrelated_entries_untouched`), preserving the file's mode
(`test_install_preserves_the_file_mode`) and the entry's own execution options
(`test_wrapping_preserves_the_entrys_execution_options`).

It refuses rather than guessing:

- an entry that is already wrapped — it never wraps a wrapper
  (`test_install_never_wraps_the_wrapper`), never wraps the same artifact twice
  under a different path
  (`test_an_identical_artifact_at_a_different_path_is_not_wrapped`), and refuses
  a second install instead of reporting success
  (`test_a_second_install_refuses_instead_of_reporting_success`);
- a config it cannot read, is not UTF-8, is not valid JSON, has the wrong shape,
  carries duplicate keys, carries NaN, or nests past the parser
  (`test_install_refuses_an_unreadable_config`,
  `test_install_refuses_a_config_that_is_not_utf8`,
  `test_install_refuses_invalid_json_without_mutating`,
  `test_install_refuses_an_invalid_shape_without_mutating`,
  `test_install_refuses_duplicate_json_keys_rather_than_dropping_data`,
  `test_install_refuses_a_config_with_nan`,
  `test_install_refuses_a_config_nested_past_the_parser`) — and in each case
  **without mutating the file**;
- an unknown server name (`test_install_refuses_an_unknown_server_name`);
- an artifact it cannot resolve
  (`test_install_refuses_when_the_artifact_cannot_be_resolved`).

**A wrapper is recognised by CONTENT, not by path**
(`test_classify_is_content_addressed_not_path_addressed`). A command that merely
names Sunglasses is not treated as wrapped
(`test_a_command_that_merely_names_us_is_not_wrapped`), nor is one that merely
names a python (`test_a_command_that_merely_names_a_python_is_unverified_not_wrapped`),
nor a marker that names a different artifact than it launches
(`test_a_marker_naming_a_different_artifact_than_it_launches_is_unverified`) or
that vouches for a command running nothing
(`test_a_marker_cannot_vouch_for_a_command_that_runs_nothing`).

## Putting it back

`uninstall` restores the retained bytes exactly
(`test_uninstall_restores_the_retained_bytes_exactly`) and reports whether that
was byte-exact (`test_uninstall_reports_byte_exact_when_the_file_did_not_move`).
If the file moved on since the install, it does the entry-only inverse and says
so (`test_uninstall_does_entry_only_inverse_when_the_file_moved`).

It refuses an unknown install
(`test_uninstall_refuses_an_unknown_install`), an entry that is no longer ours
(`test_uninstall_refuses_when_the_entry_is_no_longer_ours`), retained bytes that
do not match the record
(`test_uninstall_refuses_retained_bytes_that_do_not_match_the_record`), retained
bytes that are gone (`test_uninstall_refuses_when_the_retained_bytes_are_gone`),
a record it cannot read (`test_uninstall_refuses_a_record_it_cannot_read`), a
record whose retained path is not the canonical one
(`test_uninstall_refuses_a_record_whose_retained_path_is_not_the_canonical_one`),
and a canonical retained path that is a symlink
(`test_uninstall_refuses_when_the_canonical_retained_path_is_a_symlink`). A
record is validated as strictly as a config
(`test_uninstall_validates_a_record_as_strictly_as_a_config`).

Two configs using the same entry name do not share a record
(`test_the_same_name_in_a_second_config_does_not_steal_the_first_record`).

## What happens if the machine stops in the middle

This is the part the transaction exists for.

- An interrupted write leaves the original intact
  (`test_interrupted_write_leaves_the_original_intact`) and no temp file behind
  (`test_interrupted_write_leaves_no_temp_file_behind`).
- A crash **before** the replace is resumed by the next install
  (`test_install_resumes_a_transaction_that_crashed_before_the_replace`); a crash
  **after** it is recovered by uninstall
  (`test_uninstall_recovers_a_transaction_that_crashed_after_the_replace`).
- An unreadable completed record falls back to the journal
  (`test_uninstall_recovers_from_the_journal_when_the_completed_record_is_unreadable`),
  and journal recovery refuses a target edited since the crash
  (`test_journal_recovery_refuses_a_target_edited_since_the_crash`) or a retained
  path outside the record directory
  (`test_journal_recovery_refuses_a_retained_path_outside_the_record_directory`),
  while still restoring the state actually left behind
  (`test_journal_recovery_still_restores_the_state_we_actually_left`).
- A half-written journal is removed rather than left to be read
  (`test_a_half_written_journal_is_removed_not_left_behind`).
- A failed record write restores the target
  (`test_a_failed_record_write_restores_the_target`), and a failed rollback keeps
  the only way back (`test_a_failed_rollback_keeps_the_only_way_back`).
- Every I/O fault in the transaction surfaces as **one typed refusal**
  (`test_every_transaction_io_fault_is_one_typed_refusal`).

## Concurrency, and the bound on what is kept

An interrupted cleanup leaves a note naming the bytes it moved, so another
process can put them back. Two rules govern those notes, and both exist because
a review found the absence of them:

- **A note is identified by what it names, what that should hash to, and who
  wrote it** — never by filename alone — and a cleanup never removes a note it
  did not author.
- **What is kept is bounded by the evidence still owed**, one private note per
  outstanding held file, and never one per contested cleanup or per crash. Two
  controls drive this against real killed processes, including the case where a
  new process reports a dead one's pid
  (`test_a_killed_forget_does_not_leave_an_alias_per_death`,
  `test_a_killed_forget_does_not_leave_an_alias_per_death_with_a_reused_pid`),
  and a third counts what is kept across contested cleanups that return
  (`test_contested_forgets_keep_every_held_file_named`).

## Known limitations, stated rather than discovered

- The writer lock lives under `serve.state_root()`, so two transactions running
  under different `HOME` values lock different files and do not serialise
  against each other.
- Locking reads `flock` where it exists and `None` where it does not, because
  `fcntl` is POSIX-only while the README promises Windows.
- Inode reuse is neither proven nor handled.

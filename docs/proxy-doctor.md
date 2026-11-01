# The doctor

Where a claim below names a test, that test holds it. A claim with no test named
is a description of the behaviour, not a guarantee.

## What it answers

The doctor inventories the MCP configs it can find and reports, per entry,
whether that entry actually runs through Sunglasses. It answers three different
questions and refuses to fold them into one:

1. this route is wrapped and verified;
2. this route is direct — I looked, and nothing is protecting it;
3. I could not look.

## Exit codes, and why 3 is not a failure

`1 > 2 > 3 > 0`, in that precedence (`process_exit_code`).

| code | meaning |
|---|---|
| `1` | a real failure: the self-test ran and did not pass, or a launched route failed |
| `2` | operational: a file we could not open |
| `3` | incomplete: genuine doubt about a route, or the self-test could not come up (no `initialize` answer, or no process groups) |
| `0` | clean |

**A self-test that never ran is 3, not 1** (`test_an_unavailable_self_test_exits_three_not_one`):
an instrument that was not run did not fail in front of us, and it is never 0 either.
One that ran and did not pass stays 1 (`test_a_self_test_that_ran_and_did_not_pass_still_exits_one`).

**A clean inventory in which every route is direct is 3, not 0 and not 2**
(`test_a_clean_direct_inventory_is_still_3_not_2`). A tool that returns 0 there
tells you that you are safe because it did not check.

A file the doctor cannot read is 2 and the file is named
(`test_an_unreadable_source_is_exit_2_and_names_the_file`). An unsearchable
parent directory is reported as unreadable, not as absent
(`test_an_unsearchable_parent_is_named_unreadable_not_absent`), while a
genuinely absent source is still absent
(`test_a_genuinely_absent_source_is_still_absent`). A config with duplicate keys
is unreadable rather than quietly resolved
(`test_a_duplicate_key_config_is_unreadable_not_quietly_resolved`).

A failed self-test outranks an unreadable source
(`test_a_failed_self_test_outranks_an_unreadable_source`), because an instrument
that has failed has no standing to report on anything else.

## It shares the installer's judgement rather than repeating it

The doctor classifies entries with the installer's own classifier
(`test_the_doctor_classifies_with_installs_classifier`) and defines no second one
(`test_the_doctor_defines_no_second_classifier`), nor a second exception family
(`test_the_doctor_defines_no_second_exception_family`). The two never disagree
about the same entry (`test_the_doctor_and_install_never_disagree`), and an
unwrapped entry reads direct (`test_an_unwrapped_entry_reads_direct`).

What counts as the artifact is the proxy entry point, not the interpreter that
would run it (`test_artifact_identity_is_the_proxy_entry_point_not_the_interpreter`).
**A build with no entry point verifies nothing, and says so**
(`test_a_build_with_no_entry_point_verifies_nothing`).

## Launching a route: `--launch-routes`

`doctor --launch-routes` starts each wrapped route in your own `~/.claude.json` once
(`sunglasses/proxy/route_launch.py`). It starts your server through the proxy with a
scratch state root and verifies the handshake and a ping. The launched check does not
read or write your approvals, receipts or captures, and does not test your policy (the
inventory part of `doctor` still reads your approval records, as it always does).

- **Only your own file.** An entry from a project `.mcp.json` is never started, even if
  that file is a link to your user file, and naming it with `--config` does not change
  that. To verify a project entry, move it into your own `~/.claude.json`. An entry from a
  `--config` file is started only when the path you give is written as your own
  `~/.claude.json`: the test is the path as written, so your own file may itself be a link,
  but another path that links to it, or a path with `..`, is not accepted. The classifier
  checks the marker and the start of the argument list, not what follows the `--`, so a
  file that carries this installation's artifact path and digest can reach WRAPPED with
  any command after it; a route from a project or other file is `NOT_RUN` for that reason.
- **A scratch state root.** `--state-root <folder>` is put before the first `--`, so it is
  the last one the proxy reads; the folder is created 0700 inside a private 0700 folder.
  The command, arguments, environment, working folder and `HOME` are yours, unchanged.
  The folders are removed when the run ends, including on Ctrl-C and TERM (a SIGKILL cannot
  be caught, so it leaves them).
- **What is sent.** `initialize`, `notifications/initialized` and `ping`, then the
  connection is closed. `tools/list` and `tools/call` are never sent.
- **Verdicts.** `PASS`: `initialize` answered with a result (up to 19 s), the
  `notifications/initialized` frame written, `ping` answered with a result inside the
  2250 ms bound, and after the close the proxy exits 0 and no process group seen below it
  remains. `FAIL`: `initialize` was answered and a later step was not, whatever the clock
  says, including a frame that could not be written, a server whose group was never seen
  (it cannot be shown gone) and one that exits at once. `NOT_RUN` (3): `initialize` was not
  answered in time, the entry cannot be started as written, or it is a file that is never
  started.
- **A server that ignores a closed input.** If the server keeps running after its input
  closed and the proxy then stops it, the route is still `PASS` (the proxy did what it is
  for) and the run prints `<name>: server kept running after its input closed; the proxy
  stopped it` to stderr. The proxy has up to 8 s to do that, which is its own stop: up to
  5 s for its reader to finish, then 2 s of grace for the server's group, and a 1 s margin.
- **The process list.** The groups below the proxy are read, with `ps` or from `/proc`
  where `ps` cannot be run, while the route waits for `initialize` and again before it is
  stopped; they are not read during the ping and exit waits. Every group seen is kept and
  stopped on every way out. Each read ends at its limit (1 s while a route runs, 3 s for
  the check before the first start) or at the route's own 30 s limit, whichever comes
  first, and a read that is cut short is not a result. On the Linux `/proc` path that
  limit is checked between entries, so one entry that blocks is not interrupted. If
  neither source can be read before a start, no route is started. If the list is lost
  while a route runs, the groups already seen are still stopped. For a server whose group
  was never seen the proxy is asked to stop it by closing its input and given up to 8 s;
  only if the launcher has to kill the proxy before the server was seen, or a group it saw
  is still there at the end, does the run say a process may still be running.
- **Limits.** 16 routes, and a route is started only if a whole 30 s is left of the 120 s.
  Each route has one 30 s limit on one clock, from its start to the end of its cleanup,
  and every wait in it is cut to what is left of it, the waits after a kill included: up to 19 s for `initialize` (less when that would leave under 8 s for the proxy
  to stop), 2.5 s for the ping, up to 8 s for the proxy to exit, and 2 s for the groups to
  go. A route out of time before `initialize` is answered is `NOT_RUN` and says so; after
  it, a step left undone is `FAIL`. After a kill the launcher waits for the process (up to
  2 s) and for its output reader (up to 2 s), each cut to what is left of the route; when
  nothing is left it does not wait, and the run says a process may still be running if a
  group is still there.
- **What is printed.** One line to stderr per start: the name, the file label (`user` or
  `config`), and the program's file name. Arguments, environment, working folder and the
  route's output are never printed.
- **Ctrl-C and TERM.** The routes' processes and the private folders are stopped and
  removed, one line goes to stderr, and the exit is 130 or 143 without a traceback. If a
  process could not be shown to have stopped (a group still there when the time ran out,
  or the proxy had to be killed before its server's group was seen), the line says it may
  still be running.

Exit 0 means every configured route is wrapped and answered; the self-test passing alone
never gives 0.

## The self-test, and what makes a run valid at all

The doctor runs a live self-test (`sunglasses/proxy/live_selftest.py`): it starts the
installed proxy in front of the bundled echo server, in a private 0700 folder with
`HOME` pointed into it, and reports the five checks below. Without `--launch-routes` it does not start any
server from your config, it runs before any approval exists and writes none, and so
it does not exercise the content scan. It is not proof about one of your routes: with
the self-test passed and no route verified the report says "self-test passed; no
route to verify" and the exit is 3.

| check | what it shows |
|---|---|
| `initialized` | the proxy answers `initialize` with the same answer the echo server gives to that request, value for value |
| `s1_forward_byte_equal` | the bytes the echo server received equal the bytes the client wrote. This is the **request** side: the proxy re-serialises its replies, so a reply is value-equal, not byte-equal |
| `s2_block_schema` | a `tools/list` and a `tools/call` before any approval each get the withheld reply (`-32070`, `SUNGLASSES_WITHHELD`, `APPROVAL_REQUIRED`, rule `S4`, `not_run`), and neither of the client's requests reaches the echo server |
| `deadline` | the `ping` is answered with an empty result and, with the two withheld replies, all three come back within the bound. The clock starts before the second frame is written and stops at the last reply (start-up is not charged to it) |
| `disconnect` | closing stdin makes the proxy exit 0 and leaves no process in the echo server's group or in the proxy's own |

A spawn that has not answered `initialize` in 20 seconds (or exits first) did not
come up: nothing was checked, the report says so, and the exit is 3. The same
holds when the operating system will not make the private folder or start the
proxy, and when the whole self-test uses its 60-second allowance with nothing yet
failed. A check that has already failed stays failed (1), with one exception: a
control that could not be started makes the whole self-test unavailable (3), even
if a check had failed. A deadline miss after `initialize` is a failure, 1.

The three rigged controls have to run, and be caught, for the checks to mean
anything. If the process for one of them cannot be started, that control is
**not run**: it is not reported as failed (which would read as caught). The whole
self-test is then reported as not run, naming the control, every check keeps the
state it really had, and the exit is 3.

The private folder and every process group are cleaned up when the run ends
normally, when an error occurs inside it, and on SIGTERM, SIGHUP or SIGINT
(Ctrl-C, which then prints one line to stderr and exits 130). Each wait during the clean-up
has a limit of a few seconds; a descendant that still holds a pipe after that
is abandoned, not waited for. A SIGKILL cannot be caught, so it leaves the
folder behind.

When a live or injected self-test is available, the doctor runs its own checks
against controls that are supposed to FAIL before reporting on anything. In that
contract a run is valid only when **all checks pass and all
controls fail** (`test_all_checks_pass_and_all_controls_fail_is_the_only_valid_run`).

- A control that PASSES voids the whole run
  (`test_a_control_that_passes_voids_the_whole_run`) — an instrument that cannot
  detect a fault it was handed cannot be trusted about one it was not.
- A missing required control voids the run
  (`test_a_missing_required_control_voids_the_run`), and the skipped-invocation
  control is required rather than optional
  (`test_the_skipped_invocation_control_is_required_not_optional`).
- A route's results never overwrite the self-test's checks
  (`test_the_self_tests_checks_are_not_overwritten_by_a_route`).
- A check verdict carrying an exception string is dropped rather than counted
  (`test_a_check_verdict_carrying_an_exception_string_is_dropped`).

## Deadlines are their own class

A route that answers too late is not a route that answered wrongly.

- A deadline miss is its own class, not a schema miss
  (`test_a_deadline_miss_is_its_own_class_not_a_schema_miss`), and a schema miss
  is not reported as a deadline
  (`test_a_schema_miss_is_not_reported_as_a_deadline`).
- A deadline miss is a real failure, not a warning
  (`test_a_deadline_miss_is_a_real_failure_not_a_warning`), and exits 1 like any
  other self-test failure
  (`test_a_deadline_miss_exits_1_like_any_other_self_test_failure`).
- The report prints the measured figure beside the bound
  (`test_the_report_prints_measured_beside_bound`), the measured figure is taken
  by the doctor rather than handed to it
  (`test_the_measured_figure_is_taken_and_not_handed_to_us`), and the bound is
  the contract's figure and is not configurable
  (`test_the_bound_is_the_contracts_figure_and_is_not_configurable`).

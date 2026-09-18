# The doctor

> **Status: PENDING (#180).** This page describes a branch that has not merged,
> stacked on #177. It must not be published before the code it documents.
>
> **There is no `sunglasses doctor` subcommand on this branch.** The doctor is
> `sunglasses/proxy/doctor.py` and is reached through `doctor.run(...)`. If a
> subcommand lands later, this page needs a line, not a rewrite.

Every claim below names the control that proves it. Where no control is named,
no claim is made.

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
| `1` | a real failure: the self-test failed, or a launched route failed |
| `2` | operational: a file we could not open |
| `3` | incomplete: genuine doubt about a route |
| `0` | clean |

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
(`test_a_build_with_no_entry_point_verifies_nothing`) — which is the state this
release ships in.

## The self-test, and what makes a run valid at all

Before reporting on anything, the doctor runs its own checks against controls
that are supposed to FAIL. A run is valid only when **all checks pass and all
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

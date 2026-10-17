"""Read one finished CI run and print what tests/ci_shard.py needs to be re-measured.

    python3 tools/ci_durations.py <run-id> [--python 3.12] [--job-filter integrity] [--repo OWNER/NAME]
    python3 tools/ci_durations.py --logs part1.log part2.log      # logs already on disk

It prints three things:

  1. the wall clock of every matching job (completedAt - startedAt),
  2. the 20 slowest single tests, and
  3. a COST block for tests/ci_shard.py: seconds per test FILE (setup + call +
     teardown, summed over every log given, so both shards of one interpreter),
     every file at 60 s or more, and DEFAULT_COST as the mean of the rest.

The numbers come from pytest's own `--durations=0` section in each job log, so the
run must have been made with it (the integrity jobs are). Nothing is written; paste
the COST block by hand after reading the wall clocks.
"""
import argparse
import collections
import datetime
import json
import re
import subprocess
import sys

THRESHOLD = 60
TOP_TESTS = 20
_DURATION = re.compile(r"(?<![\w.])(\d+(?:\.\d+)?)s (call|setup|teardown)\s+(\S+::.*?)\s*$")


def parse_durations(text):
    """{test id: seconds} from pytest `--durations` lines; setup, call and teardown of one test are added."""
    out = collections.Counter()
    for line in text.splitlines():
        m = _DURATION.search(line)
        if m:
            out[m.group(3)] += float(m.group(1))
    return out


def per_file(per_test):
    files = collections.Counter()
    for test_id, seconds in per_test.items():
        files[test_id.split("::", 1)[0]] += seconds
    return files


def cost_block(files, threshold=THRESHOLD):
    """The text to paste over the COST table of tests/ci_shard.py."""
    big = {f: s for f, s in files.items() if s >= threshold}
    rest = [s for f, s in files.items() if f not in big]
    default = round(sum(rest) / len(rest)) if rest else 0
    lines = [f"DEFAULT_COST = {default}", "", "COST = {"]
    for f, s in sorted(big.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f'    "{f}": {round(s)},')
    lines.append("}")
    return "\n".join(lines)


def _gh(args):
    done = subprocess.run(["gh", *args], capture_output=True, text=True)
    if done.returncode:
        sys.exit(f"gh {' '.join(args)} failed: {done.stderr.strip()[:300]}")
    return done.stdout


def _wall(job):
    a, b = job.get("startedAt"), job.get("completedAt")
    if not a or not b:
        return None
    parse = lambda s: datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    return int((parse(b) - parse(a)).total_seconds())


def run_jobs(run_id, repo, python, job_filter):
    jobs = json.loads(_gh(["run", "view", str(run_id), "-R", repo, "--json", "jobs"]))["jobs"]
    keep = [j for j in jobs if job_filter in j["name"] and (python is None or f"({python}," in j["name"].replace(" ", ""))]
    if not keep:
        sys.exit(f"no job in run {run_id} matches filter {job_filter!r} python {python!r}: "
                 f"{sorted(j['name'] for j in jobs)[:8]}")
    return keep


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("run_id", nargs="?")
    ap.add_argument("--repo", default="sunglasses-dev/sunglasses")
    ap.add_argument("--python", help="only jobs of this interpreter, e.g. 3.12 (the slowest in the matrix)")
    ap.add_argument("--job-filter", default="integrity")
    ap.add_argument("--logs", nargs="+", help="read these log files instead of fetching a run")
    args = ap.parse_args(argv)

    texts = []
    if args.logs:
        for p in args.logs:
            with open(p, errors="replace") as fh:
                texts.append(fh.read())
    else:
        if not args.run_id:
            ap.error("give a run id or --logs")
        jobs = run_jobs(args.run_id, args.repo, args.python, args.job_filter)
        print("WALL CLOCK (job, completedAt - startedAt)")
        for j in sorted(jobs, key=lambda j: j["name"]):
            wall = _wall(j)
            print(f"  {j['name']:<24} {'running' if wall is None else f'{wall // 3600}:{wall % 3600 // 60:02d}:{wall % 60:02d}'}"
                  f"  {j.get('conclusion') or j.get('status')}")
        for j in jobs:
            texts.append(_gh(["api", f"repos/{args.repo}/actions/jobs/{j['databaseId']}/logs"]))

    per_test = collections.Counter()
    for t in texts:
        per_test.update(parse_durations(t))
    if not per_test:
        sys.exit("no `--durations` lines found: the run was not made with --durations=0")
    files = per_file(per_test)
    print(f"\n{len(per_test)} tests in {len(files)} files, {round(sum(per_test.values()))} s of test time over {len(texts)} log(s)")
    print(f"\nTOP {TOP_TESTS} TESTS")
    for test_id, s in per_test.most_common(TOP_TESTS):
        print(f"  {s:8.1f}s  {test_id[:120]}")
    print("\nCOST BLOCK for tests/ci_shard.py\n")
    print(cost_block(files))


if __name__ == "__main__":
    main()

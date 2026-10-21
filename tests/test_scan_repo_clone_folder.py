"""`scan --repo` clones into a private folder made for each run and removes it again.

The folder is removed on every way out: the normal end, a failed or timed-out clone, a
refusal after the clone, and an exception. A scan that cannot start is one refusal with
exit 2 and one document.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

import pytest

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"]


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "origin"
    root.mkdir()
    (root / "README.md").write_text("A plain readme.\n", encoding="utf-8")
    subprocess.run(GIT + ["init", "-q"], cwd=root, check=True)
    subprocess.run(GIT + ["add", "README.md"], cwd=root, check=True)
    subprocess.run(GIT + ["commit", "-q", "-m", "init"], cwd=root, check=True)
    return "file://" + str(root)


def _scan(url, tmp, *extra):
    env = dict(os.environ, TMPDIR=str(tmp))
    return subprocess.run([sys.executable, "-m", "sunglasses", "scan", "--repo", url,
                           "-o", "json", *extra],
                          capture_output=True, text=True, timeout=300, env=env)


def _derived_name(url):
    return "sunglasses-scan-" + hashlib.md5(url.encode()).hexdigest()[:10]


def test_an_existing_link_in_the_temp_folder_does_not_stop_the_scan(tmp_path, repo):
    work = tmp_path / "tmp"
    victim = tmp_path / "victim"
    work.mkdir()
    victim.mkdir()
    (victim / "keep.txt").write_text("keep\n", encoding="utf-8")
    os.symlink(victim, work / _derived_name(repo))
    out = _scan(repo, work)
    assert out.returncode == 0, out.stderr
    assert "Traceback" not in out.stderr
    assert json.loads(out.stdout)["inspection_complete"] is True
    assert (victim / "keep.txt").read_text(encoding="utf-8") == "keep\n"


def test_an_existing_folder_in_the_temp_folder_is_left_alone(tmp_path, repo):
    work = tmp_path / "tmp"
    (work / _derived_name(repo)).mkdir(parents=True)
    (work / _derived_name(repo) / "keep.txt").write_text("keep\n", encoding="utf-8")
    out = _scan(repo, work)
    assert out.returncode == 0, out.stderr
    assert (work / _derived_name(repo) / "keep.txt").exists()


def test_the_clone_folder_is_removed_after_a_scan(tmp_path, repo):
    work = tmp_path / "tmp"
    work.mkdir()
    out = _scan(repo, work)
    assert out.returncode == 0, out.stderr
    assert [p.name for p in work.iterdir() if p.name.startswith("sunglasses-scan-")] == []


def test_a_failed_clone_is_refused_and_leaves_no_folder(tmp_path):
    work = tmp_path / "tmp"
    work.mkdir()
    out = _scan("file://" + str(tmp_path / "missing"), work)
    assert out.returncode == 2
    assert json.loads(out.stdout)["scanned"] is False
    assert [p.name for p in work.iterdir() if p.name.startswith("sunglasses-scan-")] == []


def _leftovers(work):
    return [p.name for p in work.iterdir() if p.name.startswith("sunglasses-scan-")]


def _run_in_process(repo, output, capsys):
    from sunglasses import cli
    args = cli.argparse.Namespace(json=output == "json", output=output, verbose=False, max_files=None,
                                  skip_lockfiles=False, channel="file", repo=repo, directory=None)
    with pytest.raises(SystemExit) as stop:
        cli._scan_repo(args, cli.SunglassesEngine())
    return stop.value.code, capsys.readouterr()


@pytest.fixture
def work(tmp_path, monkeypatch):
    folder = tmp_path / "tmp"
    folder.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(folder))
    return folder


def test_two_runs_do_not_share_a_folder(tmp_path, repo, work, monkeypatch):
    from sunglasses import cli
    real_run = subprocess.run
    destinations = []

    def record(argv, *a, **kw):
        if argv[:2] == ["git", "clone"]:
            destinations.append(argv[-1])
        return real_run(argv, *a, **kw)

    monkeypatch.setattr(cli.subprocess, "run", record)
    for _ in range(2):
        with pytest.raises(SystemExit) as stop:
            cli._scan_repo(cli.argparse.Namespace(json=True, output="json", verbose=False, max_files=None,
                                                  skip_lockfiles=False, channel="file", repo=repo,
                                                  directory=None), cli.SunglassesEngine())
        assert stop.value.code == 0
    assert len(destinations) == 2
    assert destinations[0] != destinations[1]
    assert all(os.path.dirname(d) == str(work) for d in destinations)
    assert _leftovers(work) == []


@pytest.mark.parametrize("output", ["human", "json", "sarif"])
def test_the_folder_is_removed_after_every_kind_of_normal_end(repo, work, capsys, output):
    code, _ = _run_in_process(repo, output, capsys)
    assert code == 0
    assert _leftovers(work) == []


@pytest.mark.parametrize("output", ["human", "json", "sarif"])
def test_a_refusal_after_the_clone_removes_the_folder(repo, work, capsys, monkeypatch, output):
    from sunglasses import cli

    def refuse(_root):
        raise PermissionError("root changed")

    monkeypatch.setattr(cli, "_open_root", refuse)
    code, seen = _run_in_process(repo, output, capsys)
    assert code == 2
    if output != "human":
        assert json.loads(seen.out)["scanned"] is False
    assert _leftovers(work) == []


@pytest.mark.parametrize("breakage", ["_load_extractors", "_walk_repo_files_with_skips"])
@pytest.mark.parametrize("output", ["human", "json", "sarif"])
def test_an_exception_after_the_clone_removes_the_folder(repo, work, capsys, monkeypatch, output, breakage):
    from sunglasses import cli

    def explode(*a, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, breakage, explode)
    args = cli.argparse.Namespace(json=output == "json", output=output, verbose=False, max_files=None,
                                  skip_lockfiles=False, channel="file", repo=repo, directory=None)
    with pytest.raises(RuntimeError):
        cli._scan_repo(args, cli.SunglassesEngine())
    assert _leftovers(work) == []


def test_an_exception_while_scanning_a_file_removes_the_folder(repo, work, monkeypatch):
    from sunglasses import cli

    class Broken(cli.SunglassesEngine):
        def scan_file(self, *a, **kw):
            raise RuntimeError("boom")

    args = cli.argparse.Namespace(json=True, output="json", verbose=False, max_files=None,
                                  skip_lockfiles=False, channel="file", repo=repo, directory=None,
                                  file_deadline=0)
    with pytest.raises(RuntimeError):
        cli._scan_repo(args, Broken())
    assert _leftovers(work) == []


def test_a_clone_that_times_out_is_one_refusal_and_leaves_no_folder(repo, work, capsys, monkeypatch):
    from sunglasses import cli

    def slow(argv, *a, **kw):
        raise subprocess.TimeoutExpired(argv, 120)

    monkeypatch.setattr(cli.subprocess, "run", slow)
    code, seen = _run_in_process(repo, "json", capsys)
    assert code == 2
    assert json.loads(seen.out)["scanned"] is False
    assert _leftovers(work) == []


def test_git_that_cannot_be_started_is_one_refusal_and_leaves_no_folder(repo, work, capsys, monkeypatch):
    from sunglasses import cli

    def missing(argv, *a, **kw):
        raise FileNotFoundError("git")

    monkeypatch.setattr(cli.subprocess, "run", missing)
    code, seen = _run_in_process(repo, "json", capsys)
    assert code == 2
    assert json.loads(seen.out)["scanned"] is False
    assert _leftovers(work) == []


def test_a_folder_that_cannot_be_made_is_one_refusal_and_nothing_is_cloned(repo, work, capsys, monkeypatch):
    from sunglasses import cli
    cloned = []
    monkeypatch.setattr(cli.tempfile, "mkdtemp", lambda *a, **kw: (_ for _ in ()).throw(OSError("full")))
    monkeypatch.setattr(cli.subprocess, "run", lambda argv, *a, **kw: cloned.append(argv))
    code, seen = _run_in_process(repo, "json", capsys)
    assert code == 2
    assert json.loads(seen.out)["scanned"] is False
    assert cloned == []


def test_only_the_folder_this_run_made_is_removed(repo, work, capsys):
    neighbour = work / "sunglasses-scan-other"
    neighbour.mkdir()
    (neighbour / "keep.txt").write_text("keep\n", encoding="utf-8")
    code, _ = _run_in_process(repo, "json", capsys)
    assert code == 0
    assert (neighbour / "keep.txt").exists()
    assert _leftovers(work) == ["sunglasses-scan-other"]

"""
The MCP Bundle (`mcpb/manifest.json` + `scripts/build_mcpb.py`) stays true to
the server it wraps.

The manifest is a fourth place the release version is written down, and it
names the server's tools a second time, so both can drift silently: bump the
package and the Claude Desktop listing would still say the old version, or add
a tool and the listing would not show it. These tests tie the manifest to
`sunglasses.__version__` and to what `handle_tools_list` actually returns, and
run the builder end to end on a wheel assembled from this tree.

The negative controls at the bottom prove each reader can fail.
"""
from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

import sunglasses
from sunglasses.mcp import handle_tools_list

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "mcpb" / "manifest.json"

_spec = importlib.util.spec_from_file_location("build_mcpb", ROOT / "scripts" / "build_mcpb.py")
build_mcpb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_mcpb)


def _manifest() -> dict:
    assert MANIFEST_PATH.is_file(), f"{MANIFEST_PATH} is missing"
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _server_tool_names() -> list[str]:
    return sorted(t["name"] for t in handle_tools_list({})["tools"])


def _wheel(path: Path, version: str, init_version: str | None = None) -> Path:
    """A wheel-shaped zip of this tree's `sunglasses/` with the given versions."""
    init_version = version if init_version is None else init_version
    pkg = ROOT / "sunglasses"
    with zipfile.ZipFile(path, "w") as z:
        for f in sorted(pkg.rglob("*")):
            if not f.is_file() or "__pycache__" in f.parts or f.suffix in (".pyc", ".pyo"):
                continue
            arc = f.relative_to(ROOT).as_posix()
            data = f.read_bytes()
            if arc == "sunglasses/__init__.py":
                data = data.replace(f'"{sunglasses.__version__}"'.encode(), f'"{init_version}"'.encode(), 1)
            z.writestr(arc, data)
        z.writestr(f"sunglasses-{version}.dist-info/METADATA",
                   f"Metadata-Version: 2.1\nName: sunglasses\nVersion: {version}\n")
    return path


def test_manifest_names_the_version_the_package_declares():
    got = _manifest().get("version")
    assert got == sunglasses.__version__, (
        f"mcpb/manifest.json says {got!r}, sunglasses.__version__ is "
        f"{sunglasses.__version__!r}. Bumping the release means bumping the bundle "
        f"manifest too, or the Claude Desktop listing advertises the old version."
    )


def test_manifest_lists_exactly_the_tools_the_server_lists():
    listed = sorted(t["name"] for t in _manifest()["tools"])
    assert listed == _server_tool_names()


def test_manifest_launches_the_shipped_module():
    server = _manifest()["server"]
    assert server["type"] == "python"
    assert server["mcp_config"]["args"] == ["-m", "sunglasses.mcp"]
    assert server["entry_point"] == "server/lib/sunglasses/mcp.py"
    assert server["mcp_config"]["env"]["PYTHONPATH"] == "${__dirname}/server/lib"


def test_build_then_smoke_end_to_end(tmp_path):
    whl = _wheel(tmp_path / "sunglasses.whl", sunglasses.__version__)
    out = build_mcpb.build(whl, tmp_path / "out")
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
    assert names[0] == "manifest.json"
    assert "server/lib/sunglasses/mcp.py" in names
    assert not [n for n in names if "__pycache__" in n or n.endswith(".pyc")]
    result = build_mcpb.smoke(out)
    assert result["server_version"] == sunglasses.__version__
    assert result["tools"] == _server_tool_names()
    assert result["home_created"] is False


def test_build_is_deterministic(tmp_path):
    whl = _wheel(tmp_path / "sunglasses.whl", sunglasses.__version__)
    a = build_mcpb.build(whl, tmp_path / "a").read_bytes()
    b = build_mcpb.build(whl, tmp_path / "b").read_bytes()
    assert a == b


# --- negative controls: proof the readers can fail --------------------------

def test_control_a_wheel_of_another_version_is_refused(tmp_path):
    whl = _wheel(tmp_path / "old.whl", "0.0.1")
    with pytest.raises(SystemExit, match="refusing to build"):
        build_mcpb.build(whl, tmp_path / "out")


def test_control_a_wheel_whose_init_disagrees_is_refused(tmp_path):
    whl = _wheel(tmp_path / "split.whl", sunglasses.__version__, init_version="0.0.1")
    with pytest.raises(SystemExit, match="__init__.py"):
        build_mcpb.build(whl, tmp_path / "out")


@pytest.mark.parametrize("meta, init, fragment", [
    (None, "1.0", "METADATA Version: not found"),
    ("1.0", None, "__version__: not found"),
    ("0.9", "1.0", "'0.9', manifest says '1.0'"),
])
def test_control_check_versions_reports_each_drift(meta, init, fragment):
    problems = build_mcpb.check_versions({"version": "1.0"}, meta, init)
    assert any(fragment in p for p in problems), problems


def test_control_a_tool_missing_from_the_manifest_is_seen():
    listed = sorted(t["name"] for t in _manifest()["tools"])[1:]
    assert listed != _server_tool_names()

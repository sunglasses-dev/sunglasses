#!/usr/bin/env python3
"""
Build the MCP Bundle (`.mcpb`) that installs Sunglasses in Claude Desktop.

A `.mcpb` is a zip with `manifest.json` at its root. Ours wraps the MCP server
that already ships in the wheel (`python -m sunglasses.mcp`) and adds no code
of its own: the `sunglasses/` tree inside the bundle is copied byte for byte
out of a built wheel, so it is exactly what PyPI serves and it carries the same
MANIFEST.in prunes. The package is pure stdlib (install_requires is empty), so
nothing else is vendored. Images, PDFs and QR codes need the optional readers,
which are NOT in the bundle, and the manifest says so.

    python scripts/build_mcpb.py --wheel dist/sunglasses-0.6.0-py3-none-any.whl
    python scripts/build_mcpb.py --wheel <whl> --smoke      # build, then run it

The build refuses when the wheel, the manifest and the wheel's own
`sunglasses/__init__.py` do not all name one version. The output is
deterministic (sorted entries, fixed timestamps), so the same wheel always
gives the same bytes and a Release asset can be rebuilt and compared.

`--smoke` unpacks the bundle into a temporary directory and starts the server
from it exactly as the manifest's `mcp_config` would, with an isolated HOME:
initialize must answer with the bundle's version, tools/list must name the
manifest's tools, and nothing may be written outside the temporary directory.

Stdlib only. Not imported by the package, and not shipped in the wheel.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "mcpb" / "manifest.json"
LIB = "server/lib/"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
_VERSION_RE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.M)


def wheel_version(names: list[str], read) -> tuple[str | None, str | None]:
    """(METADATA Version, sunglasses/__init__.py __version__) read out of a wheel."""
    meta = [n for n in names if n.endswith(".dist-info/METADATA")]
    meta_version = None
    if len(meta) == 1:
        for line in read(meta[0]).decode("utf-8").splitlines():
            if line.startswith("Version:"):
                meta_version = line.split(":", 1)[1].strip()
                break
    init_version = None
    if "sunglasses/__init__.py" in names:
        m = _VERSION_RE.search(read("sunglasses/__init__.py").decode("utf-8"))
        init_version = m.group(1) if m else None
    return meta_version, init_version


def check_versions(manifest: dict, meta_version, init_version) -> list[str]:
    """Every reason the three versions disagree. Empty list == good."""
    want = manifest.get("version")
    problems = []
    for label, got in (("wheel METADATA Version", meta_version),
                       ("wheel sunglasses/__init__.py __version__", init_version)):
        if got is None:
            problems.append(f"{label}: not found in the wheel")
        elif got != want:
            problems.append(f"{label}: {got!r}, manifest says {want!r}")
    return problems


def package_members(names: list[str]) -> list[str]:
    """The wheel's `sunglasses/` files, never bytecode, in a stable order."""
    return sorted(n for n in names
                  if n.startswith("sunglasses/") and not n.endswith("/")
                  and "__pycache__" not in n and not n.endswith((".pyc", ".pyo")))


def build(wheel: Path, out_dir: Path, manifest_path: Path = MANIFEST) -> Path:
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    with zipfile.ZipFile(wheel) as whl:
        names = whl.namelist()
        problems = check_versions(manifest, *wheel_version(names, whl.read))
        if problems:
            raise SystemExit("refusing to build:\n  " + "\n  ".join(problems))
        members = package_members(names)
        entry = manifest["server"]["entry_point"]
        if not entry.startswith(LIB) or entry[len(LIB):] not in members:
            raise SystemExit(f"refusing to build: entry_point {entry!r} is not a file the wheel ships")
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"sunglasses-{manifest['version']}.mcpb"
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as mcpb:
            for arc, data in [("manifest.json", manifest_bytes)] + [
                    (LIB + n, whl.read(n)) for n in members]:
                info = zipfile.ZipInfo(arc, FIXED_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                mcpb.writestr(info, data)
    return out


def _rpc(proc, msg_id, method, params=None):
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": method,
                                 "params": params or {}}) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def smoke(bundle: Path) -> dict:
    """Start the bundled server the way the manifest says to and ask it two questions."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "bundle"
        with zipfile.ZipFile(bundle) as z:
            z.extractall(root)
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        cfg = manifest["server"]["mcp_config"]
        env = {k: v.replace("${__dirname}", str(root)) for k, v in cfg.get("env", {}).items()}
        env.update(HOME=str(Path(tmp) / "home"), PATH=os.environ.get("PATH", ""))
        # sys.executable, not cfg["command"]: the smoke proves the bundle, not
        # whichever python3 happens to be first on PATH.
        proc = subprocess.Popen([sys.executable, *cfg["args"]], cwd=tmp, env=env, text=True,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        try:
            init = _rpc(proc, 1, "initialize", {"protocolVersion": "2024-11-05",
                                                "capabilities": {}, "clientInfo": {"name": "smoke"}})
            tools = _rpc(proc, 2, "tools/list")
        finally:
            proc.stdin.close()
            proc.wait(timeout=30)
        stray = sorted(str(p.relative_to(root)) for p in root.rglob("__pycache__"))
        result = {
            "server_version": init["result"]["serverInfo"]["version"],
            "tools": sorted(t["name"] for t in tools["result"]["tools"]),
            "home_created": (Path(tmp) / "home").exists(),
            "pycache": stray,
        }
    problems = []
    if result["server_version"] != manifest["version"]:
        problems.append(f"server says {result['server_version']!r}, manifest {manifest['version']!r}")
    if result["tools"] != sorted(t["name"] for t in manifest["tools"]):
        problems.append(f"server lists {result['tools']}, manifest {[t['name'] for t in manifest['tools']]}")
    if result["home_created"]:
        problems.append("the server created HOME")
    if result["pycache"]:
        problems.append(f"bytecode written into the bundle: {result['pycache']}")
    if problems:
        raise SystemExit("smoke FAILED:\n  " + "\n  ".join(problems))
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--wheel", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=ROOT / "dist")
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args(argv)
    out = build(args.wheel, args.out)
    print(f"built {out} ({out.stat().st_size} bytes)")
    if args.smoke:
        print("smoke OK", json.dumps(smoke(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

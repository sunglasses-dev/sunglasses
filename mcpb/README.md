# Sunglasses as a Claude Desktop extension

`manifest.json` here describes an MCP Bundle (`.mcpb`), the one file Claude Desktop installs with a double click. It wraps the MCP server the package already ships, `python -m sunglasses.mcp`, and adds no code of its own.

The bundle needs Python 3.9 or newer on the machine. Plain text works out of the box. Images, PDFs and QR codes need the optional readers from `pip install "sunglasses[media]"`, which the bundle does not carry.

## Build

The `sunglasses/` tree inside the bundle is copied byte for byte out of a built wheel, so it is exactly what PyPI serves.

```
python scripts/build_mcpb.py --wheel dist/sunglasses-<version>-py3-none-any.whl --smoke
```

The build refuses a wheel whose version is not the manifest's. `--smoke` unpacks the result and starts the server from it the way Claude Desktop would, then checks the version and the tool list. The same wheel always gives the same bytes.

## Release

The `.mcpb` is attached to the GitHub Release of the version it was built from. It is never a loose file on the website.

## Keeping it true

`tests/test_mcpb_bundle.py` fails when `manifest.json` names a version other than `sunglasses.__version__` or a tool list other than the server's. Bumping a release means bumping `version` here too.

# Sunglasses for Claude

Sunglasses is a local input firewall for AI agents. This plugin connects Claude to the Sunglasses MCP server, which scans text and files for prompt injection, credential leaks and data exfiltration before an agent reads them.

## Before you install

Install the package first.

```
pip install sunglasses
```

It needs Python 3.9 or newer. The plugin starts the server with `python3 -m sunglasses.mcp`, so `python3` has to be the Python you installed it into. Images, PDFs and QR codes need the optional readers from `pip install "sunglasses[media]"`.

## Tools

- `scan_text` checks a piece of text and returns a decision with its findings.
- `scan_file` checks a file on your machine by its path.
- `scanner_info` reports the version and the pattern set.

## Privacy

The plugin runs one command, `python3 -m sunglasses.mcp`, from the package you installed. It adds no code of its own.

The server reads only the text you pass to `scan_text` and the file you name in `scan_file`. The scan runs on your machine. Sunglasses opens no network connection, sends nothing anywhere and keeps no copy of what it scans. It collects no data, so there is nothing to store, share or retain.

One optional reader is the exception. If you install `sunglasses[audio]` and ask `scan_file` for a DEEP scan of audio or video, the Whisper library it uses downloads its speech model the first time. What you scan still stays on your machine. Without that extra nothing is downloaded.

Questions go to https://github.com/sunglasses-dev/sunglasses/issues

## License

MIT, the same as the package. Source https://github.com/sunglasses-dev/sunglasses

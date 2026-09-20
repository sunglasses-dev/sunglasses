# SUNGLASSES MCP server — stdio transport, for registries that introspect a
# running container (Glama and anything else that speaks MCP over stdin/stdout).
#
# Two stages on purpose. The container must run the package the way a user gets
# it from PyPI, not the working tree: if the source sat next to the entrypoint,
# `python -m sunglasses.mcp` would import ./sunglasses and a packaging mistake
# — a missing pattern file, a package left out of find_packages() — would be
# invisible here and fail only for the people who pip install it. Building a
# wheel and installing it into a clean stage makes this image exercise the same
# artefact PyPI ships. scanner_info reports the pattern count, so the probe in
# the PR body proves the data landed rather than assuming it.
#
# The server is stdio JSON-RPC 2.0 with zero runtime dependencies
# (install_requires=[]), newline-delimited, logs on stderr. Entry point is
# `python -m sunglasses.mcp`, which is what server.json's runtimeArguments and
# the module docstring both name.

FROM python:3.12-slim AS build
WORKDIR /src
COPY . .
RUN pip install --no-cache-dir --upgrade build \
 && python -m build --wheel --outdir /wheels

FROM python:3.12-slim
# Unbuffered so JSON-RPC responses reach the client as they are written rather
# than sitting in a pipe buffer; the server flushes, but a stray print anywhere
# in the import path would otherwise stall an introspection probe.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY --from=build /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
# Nothing here needs root, and a scanner is exactly the thing you do not want
# running as root in someone else's infrastructure.
RUN useradd --create-home --uid 10001 sunglasses
USER sunglasses
# WORKDIR is deliberately not /src: there is no source tree in this stage, so
# the import can only resolve to the installed distribution.
WORKDIR /home/sunglasses
ENTRYPOINT ["python", "-m", "sunglasses.mcp"]

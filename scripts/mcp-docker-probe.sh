#!/usr/bin/env bash
# Prove the container RUNS the MCP server and answers introspection, which is
# what a registry (Glama) checks. Reading the Dockerfile proves nothing: this
# speaks JSON-RPC to the container over stdio and asserts on the replies.
#
#   scripts/mcp-docker-probe.sh [image]            normal probe, expects PASS
#   scripts/mcp-docker-probe.sh [image] --negative negative control, expects the
#                                                  probe to FAIL on a wrong entry
#
# Exit 0 = the assertions held. Exit 1 = they did not.
set -uo pipefail
IMAGE=${1:-sunglasses-mcp:probe}
MODE=${2:-}
EXPECTED_TOOLS="scan_file scan_text scanner_info"

# initialize · the notification a real client sends · tools/list · one real call
# (scanner_info proves the pattern DATA is in the image, not just the code)
req() {
  printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scanner_info","arguments":{}}}'
}

if [ "$MODE" = "--negative" ]; then
  echo "### NEGATIVE CONTROL — same probe, deliberately wrong entrypoint"
  OUT=$(req | docker run -i --rm --entrypoint python "$IMAGE" -m sunglasses.not_the_server 2>&1)
else
  echo "### PROBE — $IMAGE, entrypoint as built"
  OUT=$(req | docker run -i --rm "$IMAGE" 2>&1)
fi
RC=$?
echo "--- transcript (stdout+stderr) ---"; printf '%s\n' "$OUT"; echo "--- end transcript (docker rc=$RC) ---"

fail=0
chk() { if [ "$2" = 1 ]; then echo "  PASS  $1"; else echo "  FAIL  $1"; fail=1; fi; }

json=$(printf '%s\n' "$OUT" | grep '^{' || true)
has() { printf '%s\n' "$json" | jq -e "$1" >/dev/null 2>&1 && echo 1 || echo 0; }

chk "server announced itself on stderr"      "$(printf '%s\n' "$OUT" | grep -qF '[sunglasses-mcp] Starting' && echo 1 || echo 0)"
chk "initialize replied (id=1, jsonrpc 2.0)" "$(has 'select(.id==1 and .jsonrpc=="2.0") | .result.protocolVersion')"
chk "serverInfo.name == sunglasses"          "$(has 'select(.id==1) | select(.result.serverInfo.name=="sunglasses")')"
chk "tools/list replied (id=2)"              "$(has 'select(.id==2) | .result.tools')"
for t in $EXPECTED_TOOLS; do
  chk "tools/list advertises $t"             "$(has "select(.id==2) | select([.result.tools[].name] | index(\"$t\"))")"
done
chk "scanner_info call returned content"     "$(has 'select(.id==3) | .result.content[0].text')"
# NOT "no error object": with a dead entrypoint there are no replies at all and
# that phrasing passes on an empty transcript -- a check that is green because
# nothing ran. Assert the replies are PRESENT first, then that none is an error.
replies=$(printf '%s\n' "$json" | jq -r 'select(.id==1 or .id==2 or .id==3) | .id' 2>/dev/null | sort -u | tr -d '\n')
chk "all three requests got a reply (ids 1,2,3 present)" "$([ "$replies" = "123" ] && echo 1 || echo 0)"
chk "and none of those replies is an error object"       "$([ "$replies" = "123" ] && ! printf '%s\n' "$json" | jq -e 'select(.error)' >/dev/null 2>&1 && echo 1 || echo 0)"

echo
if [ "$MODE" = "--negative" ]; then
  if [ "$fail" = 1 ]; then echo "NEGATIVE CONTROL OK — the probe FAILS on a wrong entrypoint, so a PASS above means something"; exit 0
  else echo "NEGATIVE CONTROL BROKEN — the probe passed with no server running; every PASS is worthless"; exit 1; fi
fi
[ "$fail" = 0 ] && { echo "PROBE PASS"; exit 0; } || { echo "PROBE FAIL"; exit 1; }

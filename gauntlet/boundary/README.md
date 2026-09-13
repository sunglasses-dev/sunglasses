# Gate 2 boundary harness

Answers one question with evidence: **where can Sunglasses stand so a tool result is
inspected before the model sees it, and what does each position cost and miss.**

Design note: `~/.claude/state/warroom/GATE2_HARNESS_DESIGN.md` (decisions 1-6 appended
by T9). Scenario fixtures are ASTRA's, in `warroom/GATE2_SCENARIOS/`; this harness
consumes that format and does not define it.

Nothing here imports from or modifies `sunglasses/`. It is an experiment, not a product.

    destination/   the controlled sink: proves a payload LEFT
    proxy/         thin stdio MCP pass-through that can HOLD in both directions
    client/        instrumented Claude Code driver
    tests/         the harness's own tests, including the three that must be able
                   to fail the HARNESS rather than a candidate

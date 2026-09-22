# Reviewer-authored candidates — the schema

A candidate is a JSON object in its own file. **Authoring a JSON object is not
authoring a probe**, which is what makes this usable under a review contract
that forbids writing code — the restriction that made two rounds return
"0 findings (UNMEASURED)" because the reviewer could only run the author's own
fixtures.

    {
      "name":    "short-identifier",
      "expect":  "block" | "allow",
      "why":     "what this input is meant to show",
      "text":    "the exact input to scan",
      "channel": "file"        // optional; defaults to file
    }

Run them:

    zsh tools/review/sd010/p7-constructed.sh <axis...> --cases <your-dir>

Every row prints the CHANNEL it was measured on, so a result cannot be read
without knowing what produced it. A mismatch is the finding and the probe
exits non-zero.

**Put credential-shaped text in the FILE, never in a command line.** It is
fixture text and none of it opens anything, but a platform content filter reads
command text and has cut review rounds for exactly that.

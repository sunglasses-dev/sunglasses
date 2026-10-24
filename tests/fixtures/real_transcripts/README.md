# Real agent transcripts

Excerpts from public issue trackers of coding-agent projects: tool-call logs, session captures, protocol payloads, API error bodies and console output. They are the posters' own text. Each row in `MANIFEST.json` names the issue it came from; that URL is the attribution, and `licence_of_repo` records the licence the repository declares (the excerpt itself stays the poster's).

**Notice.** The texts are third-party text, quoted here for testing a scanner, with the source linked in every row. `licence_of_repo` is informational: it records what the repository declares and does not govern the text of an issue. A poster who wants an excerpt removed can open an issue and it is removed.

## What is in a row

| Field | Meaning |
| --- | --- |
| `source_url` | The public issue the excerpt came from. |
| `licence_of_repo` | The licence the repository declares, or that it declares none. |
| `label` | `ordinary` (normal work), `relay` (one agent or tool passing text to another), or `attack` (text that carries an instruction aimed at the agent). One label covers the channels that are scanned: `message`, `file`, `api_response`, `tool_output`. |
| `read` | `full` if the whole text was read by hand for its label, `screened` if its opening and its words were checked against the label rules. |
| `sha256` | Hash of the file in `texts/`. |
| `main` | The scanner's decision and the ids that fired, per channel, as of the last refresh of the record. |

## Rules for the texts

- No private sessions. Only text already public in an issue.
- Tokens, token-shaped values in authentication fields, e-mail addresses, user names in home paths and provider request ids are replaced before a text is stored; `tests/test_real_transcripts_corpus.py` fails when one of those forms is left, and checks each guard against a sample of the form it names and against its replacement.
- A text is stored byte for byte as it appears after those replacements.

## What the test enforces

The decisions are ordered allow, quarantine, block. A scan that is worse than the recorded decision fails: for an `ordinary` or `relay` text, any step up (including quarantine to block); for an `attack` text, any step down (including block to quarantine). A scan that is better passes. Holds on `ordinary` texts and allows on `attack` texts that are already recorded are the open false-positive and miss rows; fixing a rule is a separate change that also refreshes the `main` fields.

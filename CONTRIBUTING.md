# Contributing to Sunglasses

Thanks for wanting to help protect AI agents. Here's how to get started.

## Quick Setup

```bash
git clone https://github.com/sunglasses-dev/sunglasses.git
cd sunglasses
pip install -e ".[dev]"
pytest
```

## Ways to Contribute

### Add a Detection Pattern (Easiest)
1. Look at `attack-db/attacks/` for the JSON pattern format and `sunglasses/patterns.py` for the runtime patterns
2. Add your pattern with: regex, category, severity, description
3. Add a test case in `tests/`
4. Run `pytest` — all tests must pass
5. Submit a PR

### Add Language Support
We detect prompt injection in 13 languages. If you speak a language natively, you can add patterns that catch real-world injection attempts in that language.

### Report False Positives
If Sunglasses flags something that isn't an attack, open an issue with the text that triggered it. False positives hurt trust — we fix them fast.

### Improve Documentation
README improvements, examples, tutorials — all welcome.

## Rules
- Every pattern needs a test case
- Zero false positives on common text (we test against benign samples)
- Keep it simple — one pattern per PR is fine
- Be specific in PR descriptions — what does this catch?

## Code of Conduct
Be respectful. We're building security tools to protect people. Act like it.

## Questions?
Open an issue or reach out at contact@sunglasses.dev

# Local and Universal Rule Corpus

This corpus is a Gixy-style fixture set for local and universal rules.
It intentionally combines two fixture styles:

- hybrid files with many realistic unsafe directives in one server config;
- narrow target files for rules that need a specific inheritance, registry,
  htaccess, TLS, host, or parser shape.

The corpus is not used for external probing. Every case is analyzed locally
with `analyze-nginx`, `analyze-apache`, `analyze-lighttpd`, or `analyze-iis`.

`manifest.json` is the source of truth for expected rule IDs. The verifier in
`tests/test_rule_corpus_local_universal.py` fails when any default local or
universal rule is no longer covered by the corpus. Opt-in `policy-review`
rules are deliberately excluded because they require `--enable-policy-review`
and are documented as review prompts rather than default findings.

Current coverage:

- 24 total cases;
- 5 Nginx cases;
- 7 Apache cases, including `.htaccess` discovery;
- 6 Lighttpd cases;
- 6 IIS cases, including a local SChannel JSON registry export;
- 290/290 default local and universal rules covered;
- 0 external rules covered by design.

Run only this corpus:

```powershell
$env:PYTHONPATH=(Resolve-Path src).Path
pytest tests/test_rule_corpus_local_universal.py -q
```

When a new local or universal rule is added, add or update a fixture and record
the rule ID under `expected_findings` in `manifest.json`. The coverage test will
fail until that happens.

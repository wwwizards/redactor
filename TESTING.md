# Testing — redactor

## Quick start

```bash
pytest test_redactor.py -v
```

All 32 tests run in under 10 seconds. No external dependencies, no network calls.

## Test matrix

| Class | What it covers |
|---|---|
| `TestBuildReplacers` | `build_replacers()` return type; literal ordering; longest-match-first guarantee |
| `TestRedactValue` | email, public IP, private-IP exclusion, known name, device, `{local}` capture, no-match passthrough, stats accumulation |
| `TestRedactNode` | flat dict, nested dict, list, `keys_to_skip`, int/bool/None passthrough |
| `TestRedactFileJson` | JSON file redact, dry-run no-write, invalid-JSON → plain-text fallback |
| `TestRedactFilePlainText` | `plain_text=True` on a valid JSON file; `.txt` file; dry-run with `plain_text` |
| `TestCLI` | `--output`, `--dry-run`, `--stats`, `--inplace` (JSON + text), `--plain-text`, `--ext *`, default ext `.json`, in-place output label |
| `TestJsonFallbackStats` | `matched_patterns` is a sorted `list` (not a `set`) on the JSON-decode-error fallback path |

## Coverage notes

- Private-IP exclusion (`10.x`, `172.16-31.x`, `192.168.x`) explicitly asserted
- `{local}` email capture requires the client-domain pattern to appear **before** the generic email pattern in config — the test suite demonstrates this ordering requirement
- `keys_to_skip` values are asserted **not** redacted even when they contain PII-shaped strings
- `--inplace` is tested both for correct file mutation and for the `(in-place)` label in stdout
- `--ext *` glob is tested against a mixed `.json` + `.txt` directory

## Fixture patterns

`cfg_file` — a `tmp_path_factory` fixture that writes `MINIMAL_CONFIG` to a temp file and returns its path. All CLI tests receive `--config cfg_file` so they never depend on `redact-config.json` being present in the repo.

## Running subsets

```bash
# Just the engine (no I/O)
pytest test_redactor.py::TestBuildReplacers test_redactor.py::TestRedactValue test_redactor.py::TestRedactNode -v

# Just file I/O
pytest test_redactor.py::TestRedactFileJson test_redactor.py::TestRedactFilePlainText -v

# Just CLI integration
pytest test_redactor.py::TestCLI -v
```

## Known gaps / future tests

- `redact-config-f5.json` integration (F5 tmsh AS-BUILT patterns — `A.B.x.y` IP style, MAC addresses, cluster names)
- Directory scan with nested subdirectories (currently flat only)
- `--stats` output format assertions (currently only checks count presence, not exact format)
- Unicode / multi-byte content in plain-text mode

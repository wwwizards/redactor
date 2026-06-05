# redactor

**Config-driven PII redactor for JSON and plaintext operational files** Zero external dependencies. Pure Python stdlib (re, json, pathlib, argparse).

## What It Does

Redacts personally identifiable information (PII) from JSON files or plain text using configurable patterns:
- Email addresses (preserves local part for distinguishability)
- IP addresses — full redaction OR first-two-octet masking (see below)
- Azure GUIDs (subscription IDs, resource IDs)
- Client-specific proper nouns (names, orgs, devices)
- Custom regex patterns with capture-group backreferences

**Use case:** Sanitize AI agent handoff files, logs, tmsh AS-BUILT captures, or config dumps before sharing publicly or with support.

## Features

- **Zero dependencies** — stdlib only (`re`, `json`, `pathlib`, `argparse`, `sys`); `pyyaml` optional for YAML rule files
- **Config-driven** — layered YAML/JSON rules, last-definition-wins merge
- **Built-in defaults** — email + public-IP redaction works out-of-the-box with zero config files
- **Recursive** — handles nested JSON structures
- **Preserves structure** — JSON formatting and hierarchy maintained
- **Plain text mode** — `--plain-text` flag bypasses JSON parsing entirely (use for `.txt`, `.log`, tmsh captures, syslog)
- **Pipe mode** — omit `--input` (or use `-`) to read from stdin; output to stdout; stats to stderr
- **In-place editing** — `--inplace` overwrites source file(s) directly
- **All-extension scan** — `--ext *` processes every file type in a directory
- **Backreference replacements** — use `\1`, `\2` etc. in replacement strings (e.g. partial IP masking)
- **Dry-run mode** — preview changes before writing
- **Stats reporting** — see what was redacted and where

## Changelog

### v0.4.0 — 2026-06-05 (breaking)

**Breaking changes:**
- `redact-config.example.json` replaced by `redactor-rules.base.yaml`. The old
file is still loaded with a deprecation warning — rename it to silence.
- `redact-config.json` (private copy) still loaded as a legacy fallback, but
`redactor-rules.custom.yaml` is the new override path.
- `--config` now **layers on top of** auto-discovered base+custom rules instead
of replacing them. Use `--config` to inject a domain-specific pack (e.g. `--config redactor-rules.f5.yaml`) without losing the base patterns.

**New features:**
- Layered config system: built-in defaults → base YAML → custom YAML → `--config`
- YAML rule files with `pyyaml` (optional dep): use `pattern: |` block scalars
to write regex without double-escaping backslashes
- `merge_configs()` public API: programmatic layer merging for library use
- `BUILTIN_DEFAULTS` constant: email + public-IP redaction with zero files

### v0.3.0 — 2026-06-05
- Pipe mode: `cat file | redactor.py --plain-text` (stdin → stdout, stats → stderr)
- Config fallback: auto-uses `redactor-rules.base.yaml` when
`redact-config.json` is absent (fresh clone works OOB)
- `--inplace` + stdin guard (exits non-zero)

### v0.2.0 — 2026-06-04
- `--plain-text` flag (skip JSON parsing, raw regex on any file)
- `--inplace` flag (overwrite input file, no suffix/subdir)
- `--ext *` (process all file types in directory scans)
- `ipv4_mask_first_two_octets` backreference pattern in example config
- 36-test pytest suite (`test_redactor.py`)

### v0.1.0 — 2026-06-04
- Initial release: JSON redaction, recursive dir scan, config-driven patterns

### Quick start (no install)
```bash
git clone https://github.com/wwwizards/redactor.git
cd redactor
python redactor.py --help
```

### Pip install (editable)
```bash
git clone https://github.com/wwwizards/redactor.git
cd redactor
pip install -e .
```

### Standalone script
Just copy `redactor.py` to your project. It works out-of-the-box with built-in defaults (email + public IP). To add rules, drop a `redactor-rules.custom.yaml` next to it.

## Usage

### Basic usage
```bash
# Redact a single file
python redactor.py --input handoff.json

# Redact a directory (recursive)
python redactor.py --input .AI-TRAINING --output .AI-TRAINING/public

# Dry run (preview only)
python redactor.py --input handoff.json --dry-run

# Show stats
python redactor.py --input .AI-TRAINING --stats
```

### Advanced options
```bash
# Custom config file
python redactor.py --input data.json --config my-config.json

# Custom file extension
python redactor.py --input logs/ --ext .log

# Process ALL file types in a directory
python redactor.py --input logs/ --ext *

# Treat input as plain text (skip JSON parsing)
# Use for: .txt, .log, tmsh AS-BUILT captures, AAP job stdout, syslog
python redactor.py --input capture.txt --plain-text

# Overwrite input file in place (no copy, no suffix)
python redactor.py --input capture.txt --plain-text --inplace

# Specify output location
python redactor.py --input secrets.json --output public/safe.json
```

### Pipe mode (stdin → stdout)

Omit `--input` (or use `--input -`) when stdin is a pipe. Redacted output goes to stdout; stats/errors go to stderr so downstream pipe stages stay clean.

```bash
# Basic pipe
cat capture.txt | python redactor.py --plain-text

# Chain with grep and sort (stats on stderr, invisible to downstream)
cat app.log | python redactor.py --plain-text | grep ERROR | sort

# Explicit stdin marker
python redactor.py --input - --plain-text < capture.txt

# Custom config in a pipe
cat tmsh-output.txt | python redactor.py --plain-text --config redact-config-f5.json

# Dry run via pipe — prints stats to stderr, nothing to stdout
cat file.txt | python redactor.py --plain-text --dry-run
```

**Before / after example:**

```
BEFORE                                              AFTER
─────────────────────────────────────────────────────────────────────
203.0.113.47                                 →  [IP:redacted]
alice@example.com                            →  [EMAIL:redacted]
bob.smith@contoso.com                        →  [EMAIL:redacted]
HOST-PROD-01                                 →  [VM:session-host]
```

> **Note:** `--inplace` cannot be combined with pipe mode (there is no file to
> overwrite). The tool exits with a non-zero code if both are specified.

## Configuration

### Rule resolution order (last layer wins per pattern name)

```
1. Built-in defaults        always active (email_generic, ipv4_public)
2. redactor-rules.base.yaml shipped baseline — extend or override by name
3. redactor-rules.custom.yaml  gitignored org/user overrides
4. --config <path>          explicit CLI override — always wins
```

Copy `redactor-rules.base.yaml` and edit, or create `redactor-rules.custom.yaml` with only the patterns you want to change:

```yaml
# redactor-rules.custom.yaml
patterns:
  # Override the shipped client-domain pattern with your actual domain
  - name: email_client_domain
    pattern: |
      [a-zA-Z0-9._%+\-]+@fordham\.edu
    replacement: "[EMAIL:fordham-{local}]"

  # Add a new pattern not in the base
  - name: employee_id
    pattern: "EMP-\\d{6}"
    replacement: "[EMPID:redacted]"
```

> **YAML tip:** Use `pattern: |` (block scalar) to write regex without
> double-escaping backslashes. `\b`, `\d`, `\(` are read literally.

> **pyyaml:** YAML support requires `pip install pyyaml`. JSON rule files
> (`.json`) always work without any extra deps.

### Legacy config (v0.2.0 and earlier)

`redact-config.json` / `redact-config.example.json` are still loaded with a deprecation warning. Rename to `redactor-rules.base.yaml` (preferred) or `redactor-rules.custom.json` to silence the warning.

```json
{
  "token_style": "semantic",
  
  "patterns": [
    {
      "name": "email_client",
      "pattern": "[a-zA-Z0-9._%+\\-]+@client\\.com",
      "replacement": "[EMAIL:{local}@client.example.com]"
    }
  ],
  
  "known_names": {
    "people": {
      "John Doe": "[PERSON:user-1]",
      "Jane Smith": "[PERSON:user-2]"
    },
    "devices": {
      "LAPTOP-01": "[DEVICE:client-01]"
    }
  },
  
  "keys_to_skip": ["version", "timestamp"],
  
  "output": {
    "suffix": "-REDACTED",
    "subdir": "public"
  }
}
```

### Pattern Priority

1. **Named literals first** (longest match wins) — `known_names` section
2. **Regex patterns** (in config order) — `patterns` section

### Special Replacements

- `{local}` in email replacements preserves local part:
  - `tiffany@client.com` → `[EMAIL:tiffany@client.example.com]`
  - `cto@client.com` → `[EMAIL:cto@client.example.com]`

- **Capture group backreferences** (`\1`, `\2`, ...) work natively:
  - Useful for partial masking — redact some parts of a value while preserving others

### Partial IP masking (first two octets)

Use this instead of full IP redaction when troubleshooters need the host suffix for correlation:

```json
{
  "name": "ipv4_mask_first_two_octets",
  "pattern": "\\b(\\d{1,3}\\.\\d{1,3})\\.(\\d{1,3}\\.\\d{1,3})\\b",
  "replacement": "A.B.\\2"
}
```

**Before:** `Server 203.0.113.5 connected from 198.51.100.22`
**After:** `Server A.B.113.5 connected from A.B.100.22`

Group 1 (`\1`) = first two octets (masked). Group 2 (`\2`) = last two octets (preserved).

> **Note:** Use `ipv4_mask_first_two_octets` **instead of** `ipv4_public` in your config, not alongside it — both patterns would match the same IPs.

### Partial IP masking (backreference)

To mask only the first two octets while keeping the last two for subnet context, use a capture-group backreference in the replacement string:

```json
{
  "name": "ipv4_partial_mask",
  "pattern": "\\b(\\d{1,3}\\.\\d{1,3})(\\.\\d{1,3}\\.\\d{1,3})\\b",
  "replacement": "x.x\\2"
}
```

`203.0.113.5` → `x.x.113.5` — subnet (last two octets) preserved for context.

Backreferences (`\1`, `\2`, etc.) work in any `replacement` string — they are passed directly to Python's `re.sub()` so all standard group syntax applies.

### Keys to Skip

JSON keys listed in `keys_to_skip` are preserved verbatim (useful for version numbers, timestamps, or metadata).

## Examples

### Input
```json
{
  "user": "John Doe",
  "email": "john@acme.com",
  "device": "LAPTOP-01",
  "ip": "203.0.113.42",
  "private_ip": "10.0.1.5",
  "subscription_id": "12345678-1234-1234-1234-123456789abc"
}
```

### Output
```json
{
  "user": "[PERSON:user-1]",
  "email": "[EMAIL:john@client.example.com]",
  "device": "[DEVICE:client-01]",
  "ip": "[IP:redacted]",
  "private_ip": "10.0.1.5",
  "subscription_id": "[AZURE-GUID:redacted]"
}
```

## Use Cases

- **AI agent handoffs** — sanitize context before pushing to public repos
- **Support tickets** — redact PII from logs/config dumps
- **Documentation** — create shareable examples from real data
- **Compliance** — automated PII removal for GDPR/HIPAA workflows

## Architecture

- **build_replacers()** — compiles config into ordered (regex, replacement) tuples; callables for `{local}` capture
- **redact_value()** — applies all replacers to a single string; backreference strings passed through natively via `re.subn`
- **redact_node()** — recursively walks JSON structures; honours `keys_to_skip`
- **redact_file()** — JSON or plain-text path; `plain_text=True` skips JSON parse entirely

## Development

### Run tests
```bash
pytest test_redactor.py -v
```
32 tests, ~6 seconds. See [TESTING.md](TESTING.md) for full matrix and subset commands.

## License

MIT License — see [LICENSE](LICENSE)

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Roadmap

- [ ] Pytest test suite
- [ ] CI/CD (GitHub Actions)
- [ ] PyPI package distribution
- [ ] Hash-based redaction mode (SHA256 prefix tokens)
- [ ] Multi-file diff reporting
- [ ] Config validation schema

## Credits

Built by [LogicWizards.NYC](https://logicwizards.nyc) for sanitizing AI agent handoff files in the BotSwarming workflow.

## Related Projects

- [psst](https://github.com/wwwizards/psst) — PowerShell smart test runner
- [psstel](https://github.com/wwwizards/psstel) — PowerShell telemetry module

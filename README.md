# redactor

**Config-driven PII redactor for JSON and plaintext operational files**
Zero external dependencies. Pure Python stdlib (re, json, pathlib, argparse).

## What It Does

Redacts personally identifiable information (PII) from JSON files or plain text using configurable patterns:
- Email addresses (preserves local part for distinguishability)
- IP addresses — full redaction OR first-two-octet masking (see below)
- Azure GUIDs (subscription IDs, resource IDs)
- Client-specific proper nouns (names, orgs, devices)
- Custom regex patterns with capture-group backreferences

**Use case:** Sanitize AI agent handoff files, logs, tmsh AS-BUILT captures, or config dumps before sharing publicly or with support.

## Features

- **Zero dependencies** — stdlib only, runs anywhere Python 3.7+ exists
- **Config-driven** — add new client patterns without touching code
- **Recursive** — handles nested JSON structures
- **Preserves structure** — JSON formatting and hierarchy maintained
- **Plain text mode** — `--plain-text` flag bypasses JSON parsing entirely (use for `.txt`, `.log`, tmsh captures, syslog)
- **In-place editing** — `--inplace` overwrites source file(s) directly
- **All-extension scan** — `--ext *` processes every file type in a directory
- **Backreference replacements** — use `\1`, `\2` etc. in replacement strings (e.g. partial IP masking)
- **Dry-run mode** — preview changes before writing
- **Stats reporting** — see what was redacted and where

## Installation

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
Just copy `redactor.py` and `redact-config.json` to your project.

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

## Configuration

Copy `redact-config.example.json` to `redact-config.json` and customize:

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

To mask only the first two octets while keeping the last two for subnet context,
use a capture-group backreference in the replacement string:

```json
{
  "name": "ipv4_partial_mask",
  "pattern": "\\b(\\d{1,3}\\.\\d{1,3})(\\.\\d{1,3}\\.\\d{1,3})\\b",
  "replacement": "x.x\\2"
}
```

`203.0.113.5` → `x.x.113.5` — subnet (last two octets) preserved for context.

Backreferences (`\1`, `\2`, etc.) work in any `replacement` string — they are
passed directly to Python's `re.sub()` so all standard group syntax applies.

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

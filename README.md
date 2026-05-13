# redactor

**Config-driven PII redactor for JSON handoff files**  
Zero external dependencies. Pure Python stdlib (re, json, pathlib, argparse).

## What It Does

Redacts personally identifiable information (PII) from JSON files or plain text using configurable patterns:
- Email addresses (preserves local part for distinguishability)
- IP addresses (public only, preserves RFC1918 private IPs)
- Azure GUIDs (subscription IDs, resource IDs)
- Client-specific proper nouns (names, orgs, devices)
- Custom regex patterns

**Use case:** Sanitize AI agent handoff files, logs, or config dumps before sharing publicly or with support.

## Features

- **Zero dependencies** — stdlib only, runs anywhere Python 3.7+ exists
- **Config-driven** — add new client patterns without touching code
- **Recursive** — handles nested JSON structures
- **Preserves structure** — JSON formatting and hierarchy maintained
- **Plain text fallback** — non-JSON files processed as text
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

- **build_replacers()** — compiles config into ordered (regex, replacement) tuples
- **redact_value()** — applies all replacers to a single string
- **redact_node()** — recursively walks JSON structures
- **redact_file()** — handles JSON or plain text, writes output

## Development

### Run tests (when added)
```bash
pytest test_redactor.py
```

### Lint
```bash
pylint redactor.py
```

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

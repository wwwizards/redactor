"""redactor.py - Config-driven PII redactor for JSON and plaintext operational files.
Zero external dependencies (stdlib only: re, json, pathlib, argparse).

Usage:
    python redactor.py --input .AI-TRAINING --output .AI-TRAINING/public
    python redactor.py --input path/to/file.json --dry-run
    python redactor.py --input .AI-TRAINING --stats
    python redactor.py --input capture.txt --config redact-config-f5.json --plain-text --inplace
    python redactor.py --input logs/ --ext * --plain-text --output logs/redacted/"""

import re
import json
import argparse
from pathlib import Path

# ── Config ─────────────────────────────────────────────────────────────────────

DEFAULT_CONFIG = Path(__file__).parent / "redact-config.json"

def load_config(config_path: Path) -> dict:
    with open(config_path, encoding="utf-8") as f:
        return json.load(f)

# ── Core redaction engine ──────────────────────────────────────────────────────

def build_replacers(config: dict):
    """Returns ordered list of (compiled_regex, replacement) tuples."""
    replacers = []

    # 1. Named literals first (longest match wins — sort by length desc)
    names = config.get("known_names", {})
    all_literals = {}
    for group in names.values():
        if isinstance(group, dict):
            all_literals.update(group)

    for literal, token in sorted(all_literals.items(), key=lambda x: -len(x[0])):
        escaped = re.escape(literal)
        replacers.append((re.compile(escaped), token))

    # 2. Regex patterns (in config order)
    for p in config.get("patterns", []):
        pattern = p["pattern"]
        replacement = p["replacement"]

        # Special case: email with {local} capture group
        if "{local}" in replacement:
            def make_email_replacer(repl_template):
                def replacer(m):
                    local = m.group(0).split("@")[0]
                    return repl_template.replace("{local}", local)
                return replacer
            replacers.append((re.compile(pattern, re.IGNORECASE), make_email_replacer(replacement)))
        else:
            replacers.append((re.compile(pattern, re.IGNORECASE), replacement))

    return replacers


def redact_value(value: str, replacers: list, stats: dict) -> str:
    """Apply all replacers to a single string value."""
    for pattern, replacement in replacers:
        if callable(replacement):
            new_value, n = pattern.subn(replacement, value)
        else:
            new_value, n = pattern.subn(replacement, value)
        if n > 0:
            stats["replacements"] += n
            stats["matched_patterns"].add(pattern.pattern[:40])
        value = new_value
    return value


def redact_node(node, replacers: list, skip_keys: set, stats: dict):
    """Recursively walk any JSON structure and redact string values."""
    if isinstance(node, dict):
        return {
            k: (v if k in skip_keys else redact_node(v, replacers, skip_keys, stats))
            for k, v in node.items()
        }
    elif isinstance(node, list):
        return [redact_node(item, replacers, skip_keys, stats) for item in node]
    elif isinstance(node, str):
        return redact_value(node, replacers, stats)
    else:
        return node  # int, bool, None — untouched


def redact_file(input_path: Path, output_path: Path, config: dict, dry_run: bool = False, plain_text: bool = False) -> dict:
    """Redact a single file. Returns stats dict.

    plain_text=True: skip JSON parsing entirely; apply regex patterns to the
    raw file content line-by-line.  Use for .txt, .log, tmsh captures, etc.
    When False (default), tries JSON first and falls back to plain-text on
    decode failure.
    """
    stats = {"file": str(input_path), "replacements": 0, "matched_patterns": set()}
    replacers = build_replacers(config)

    if plain_text:
        text = input_path.read_text(encoding="utf-8", errors="replace")
        redacted = redact_value(text, replacers, stats)
        if not dry_run:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(redacted, encoding="utf-8")
        stats["matched_patterns"] = sorted(stats["matched_patterns"])
        return stats

    with open(input_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            # Not JSON — treat as plain text
            text = input_path.read_text(encoding="utf-8", errors="replace")
            redacted = redact_value(text, replacers, stats)
            if not dry_run:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(redacted, encoding="utf-8")
            stats["matched_patterns"] = sorted(stats["matched_patterns"])
            return stats

    skip_keys = set(config.get("keys_to_skip", []))
    redacted_data = redact_node(data, replacers, skip_keys, stats)

    if not dry_run:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(redacted_data, f, indent=2, ensure_ascii=False)

    stats["matched_patterns"] = sorted(stats["matched_patterns"])
    return stats

# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PII redactor for JSON and plaintext files")
    parser.add_argument("--input", required=True, help="Input file or directory")
    parser.add_argument("--output", default=None, help="Output file or directory (default: <input>/public/)")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Path to redact-config.json")
    parser.add_argument("--dry-run", action="store_true", help="Report what would be redacted, don't write files")
    parser.add_argument("--stats", action="store_true", help="Print replacement counts per file")
    parser.add_argument("--ext", default=".json", help="File extension filter for directory scans (default: .json; use * for all files)")
    parser.add_argument("--plain-text", action="store_true", help="Skip JSON parsing; treat input as raw text (use for .txt, .log, tmsh captures, etc.)")
    parser.add_argument("--inplace", action="store_true", help="Overwrite input file(s) in place (no suffix, no subdir)")
    args = parser.parse_args()

    config = load_config(Path(args.config))
    input_path = Path(args.input)

    cfg_output = config.get("output", {})
    suffix = cfg_output.get("suffix", "-REDACTED")
    subdir = cfg_output.get("subdir", "public")

    # Build file list
    if input_path.is_file():
        files = [input_path]
        if args.inplace:
            output_base = None  # resolved per-file below
        elif args.output:
            output_base = Path(args.output)
        else:
            output_base = input_path.parent / subdir
    else:
        ext = args.ext
        glob_pattern = "**/*" if ext in ("*", ".*", "") else f"**/*{ext}"
        files = sorted(f for f in input_path.glob(glob_pattern) if f.is_file())
        if args.inplace:
            output_base = None
        else:
            output_base = Path(args.output) if args.output else input_path / subdir

    total_replacements = 0
    for file in files:
        if args.inplace:
            out_file = file  # overwrite in place
        else:
            rel = file.relative_to(input_path) if input_path.is_dir() else Path(file.name)
            out_name = rel.stem + suffix + rel.suffix
            out_file = output_base / rel.parent / out_name

        stats = redact_file(file, out_file, config, dry_run=args.dry_run, plain_text=args.plain_text)
        total_replacements += stats["replacements"]

        if args.dry_run or args.stats:
            status = "[DRY RUN] " if args.dry_run else ""
            print(f"{status}{file.name}: {stats['replacements']} replacements")
            if stats["matched_patterns"]:
                for p in stats["matched_patterns"]:
                    print(f"    pattern: {p}...")
        elif not args.dry_run:
            dest = file.name if args.inplace else out_file.name
            arrow = "(in-place)" if args.inplace else f"→ {dest}"
            print(f"  ✓ {file.name} {arrow} ({stats['replacements']} replacements)")

    print(f"\nTotal: {total_replacements} replacements across {len(files)} file(s)")
    if args.dry_run:
        print("(dry run — no files written)")

if __name__ == "__main__":
    main()

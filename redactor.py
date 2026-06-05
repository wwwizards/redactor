"""redactor.py - Config-driven PII redactor for JSON and plaintext operational files.
Optional dep: pyyaml (pip install pyyaml) unlocks YAML rule files.

Usage:
    python redactor.py --input .AI-TRAINING --output .AI-TRAINING/public
    python redactor.py --input path/to/file.json --dry-run
    python redactor.py --input .AI-TRAINING --stats
    python redactor.py --input capture.txt --config redactor-rules.f5.yaml --plain-text --inplace
    python redactor.py --input logs/ --ext * --plain-text --output logs/redacted/

    # Pipe mode (stdin -> stdout) -- omit --input or use --input -
    cat file.txt | python redactor.py --plain-text
    cat capture.txt | python redactor.py --plain-text | grep error | sort
    python redactor.py --input - --plain-text < file.txt

Config resolution (last layer wins per-pattern-name):
    1. Built-in defaults    -- always active, zero files needed
    2. redactor-rules.base.yaml  -- shipped baseline (replaces redact-config.example.json)
    3. redactor-rules.custom.yaml -- gitignored org/user overrides
    4. --config <path>      -- explicit CLI override, always wins"""

import re
import json
import sys
import argparse
from pathlib import Path

try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _yaml = None
    _YAML_AVAILABLE = False

# ── Built-in defaults (active with zero config files) ─────────────────────────

BUILTIN_DEFAULTS = {
    "token_style": "semantic",
    "patterns": [
        {
            "name": "email_generic",
            "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            "replacement": "[EMAIL:redacted]",
        },
        {
            "name": "ipv4_public",
            "pattern": r"\b(?!10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "replacement": "[IP:redacted]",
        },
    ],
    "known_names": {},
    "keys_to_skip": ["_comment", "version", "timestamp"],
    "output": {"suffix": "-REDACTED", "subdir": "public"},
}

# ── Config loading & merging ───────────────────────────────────────────────────

def load_config_layer(path: Path) -> dict:
    """Load a single YAML (.yaml/.yml) or JSON config file. Strips _ metadata keys."""
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        if not _YAML_AVAILABLE:
            print(
                f"[warn] pyyaml not installed -- cannot load {path.name}. "
                "Run: pip install pyyaml",
                file=sys.stderr,
            )
            return {}
        data = _yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    return {k: v for k, v in data.items() if not str(k).startswith("_")}


def merge_configs(*layers: dict) -> dict:
    """Merge config layers with last-definition-wins semantics.

    - patterns:    merged by 'name'; later layer replaces earlier by name.
    - known_names: deep-merged by group; later entries replace earlier within group.
    - keys_to_skip: union across all layers.
    - output, token_style: last layer wins.
    """
    result = {
        "token_style": "semantic",
        "patterns": [],
        "known_names": {},
        "keys_to_skip": [],
        "output": {"suffix": "-REDACTED", "subdir": "public"},
    }
    patterns_ordered: dict = {}  # name -> pattern dict, insertion-ordered

    for layer in layers:
        if not layer:
            continue
        if "token_style" in layer:
            result["token_style"] = layer["token_style"]
        if "output" in layer:
            result["output"].update(layer["output"])
        for k in layer.get("keys_to_skip", []):
            if k not in result["keys_to_skip"]:
                result["keys_to_skip"].append(k)
        for group, entries in layer.get("known_names", {}).items():
            if isinstance(entries, dict):
                if group not in result["known_names"]:
                    result["known_names"][group] = {}
                result["known_names"][group].update(entries)
        for p in layer.get("patterns", []):
            if not isinstance(p, dict) or "name" not in p:
                continue
            name = p["name"]
            clean = {k: v for k, v in p.items() if not str(k).startswith("_")}
            patterns_ordered[name] = clean

    result["patterns"] = list(patterns_ordered.values())
    return result


_LAYER_DIR = Path(__file__).parent
_LEGACY_NAMES = ("redact-config.json", "redact-config.example.json")


def discover_config_layers(explicit_path: str = None) -> dict:
    """Build merged config from the resolution chain:

      1. BUILTIN_DEFAULTS            (always active)
      2. redactor-rules.base.yaml    (shipped baseline, if present)
      3. redactor-rules.custom.yaml  (gitignored overrides, if present)
      4. --config <path>             (explicit CLI override, always wins)

    Legacy redact-config.json / redact-config.example.json are loaded with a
    deprecation warning in place of step 2 when no base YAML is found.
    """
    layers = [BUILTIN_DEFAULTS]

    # Layer 2 -- base rules
    found_base = False
    for candidate in ("redactor-rules.base.yaml", "redactor-rules.base.json"):
        p = _LAYER_DIR / candidate
        if p.exists():
            layers.append(load_config_layer(p))
            found_base = True
            break
    if not found_base:
        for legacy in _LEGACY_NAMES:
            p = _LAYER_DIR / legacy
            if p.exists():
                print(
                    f"[warn] {legacy} is deprecated -- rename to redactor-rules.base.yaml",
                    file=sys.stderr,
                )
                layers.append(load_config_layer(p))
                break

    # Layer 3 -- custom overrides
    for candidate in ("redactor-rules.custom.yaml", "redactor-rules.custom.json"):
        p = _LAYER_DIR / candidate
        if p.exists():
            layers.append(load_config_layer(p))
            break

    # Layer 4 -- explicit CLI override
    if explicit_path:
        layers.append(load_config_layer(Path(explicit_path)))

    return merge_configs(*layers)

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
        pattern = p["pattern"].strip()  # strip trailing newline from YAML block scalars
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
    parser.add_argument("--input", default=None, help="Input file or directory (omit or use - for stdin)")
    parser.add_argument("--output", default=None, help="Output file or directory (default: <input>/public/)")
    parser.add_argument("--config", default=None, help="Explicit config file (YAML or JSON). Layers on top of auto-discovered base+custom rules.")
    parser.add_argument("--dry-run", action="store_true", help="Report what would be redacted, don't write files")
    parser.add_argument("--stats", action="store_true", help="Print replacement counts per file")
    parser.add_argument("--ext", default=".json", help="File extension filter for directory scans (default: .json; use * for all files)")
    parser.add_argument("--plain-text", action="store_true", help="Skip JSON parsing; treat input as raw text (use for .txt, .log, tmsh captures, etc.)")
    parser.add_argument("--inplace", action="store_true", help="Overwrite input file(s) in place (no suffix, no subdir)")
    args = parser.parse_args()

    config = discover_config_layers(args.config)

    # ── Pipe / stdin mode ─────────────────────────────────────────────────────
    use_stdin = (args.input is None and not sys.stdin.isatty()) or args.input == "-"
    if use_stdin:
        if args.inplace:
            print("error: --inplace cannot be used with stdin", file=sys.stderr)
            sys.exit(1)
        replacers = build_replacers(config)
        stats = {"file": "<stdin>", "replacements": 0, "matched_patterns": set()}
        text = sys.stdin.read()
        redacted = redact_value(text, replacers, stats)
        if not args.dry_run:
            sys.stdout.write(redacted)
        stats["matched_patterns"] = sorted(stats["matched_patterns"])
        if args.dry_run or args.stats:
            print(f"<stdin>: {stats['replacements']} replacements", file=sys.stderr)
            for p in stats["matched_patterns"]:
                print(f"    pattern: {p}...", file=sys.stderr)
        return

    # ── File / directory mode ─────────────────────────────────────────────────
    if args.input is None:
        print("error: --input is required when not reading from a pipe", file=sys.stderr)
        sys.exit(1)

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

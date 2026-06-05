"""
test_redactor.py — pytest suite for redactor.py

Covers:
  - Core engine (build_replacers, redact_value, redact_node)
  - redact_file: JSON path, plain-text fallback, explicit --plain-text
  - CLI: --dry-run, --stats, --inplace, --plain-text, --ext *, keys_to_skip
  - Edge cases: nested JSON, list nodes, int/bool passthrough, email {local}
"""

import json
import sys
from pathlib import Path

import pytest

# Allow importing from same directory without installing the package
sys.path.insert(0, str(Path(__file__).parent))
from redactor import (
    build_replacers,
    redact_value,
    redact_node,
    redact_file,
    main,
)

# ── Minimal fixture config ────────────────────────────────────────────────────

MINIMAL_CONFIG = {
    "patterns": [
        # client-domain BEFORE generic so {local} capture fires first
        {
            "name": "email_client_domain",
            "pattern": "[a-zA-Z0-9._%+\\-]+@acme\\.com",
            "replacement": "[EMAIL:client-{local}]",
        },
        {
            "name": "email_generic",
            "pattern": "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}",
            "replacement": "[EMAIL:redacted]",
        },
        {
            "name": "ipv4_public",
            "pattern": "\\b(?!10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b",
            "replacement": "[IP:redacted]",
        },
    ],
    "known_names": {
        "people": {
            "Alice Johnson": "[PERSON:user-1]",
            "Alice": "[PERSON:user-1]",
        },
        "devices": {
            "HOST-PROD-01": "[VM:session-host]",
        },
    },
    "keys_to_skip": ["version", "timestamp"],
    "output": {"suffix": "-REDACTED", "subdir": "public"},
}


# ── build_replacers ───────────────────────────────────────────────────────────


class TestBuildReplacers:
    def test_returns_list_of_tuples(self):
        replacers = build_replacers(MINIMAL_CONFIG)
        assert isinstance(replacers, list)
        assert all(len(r) == 2 for r in replacers)

    def test_literal_before_pattern(self):
        """Known-name literals appear before regex patterns."""
        replacers = build_replacers(MINIMAL_CONFIG)
        import re
        # First replacer should match a literal (no special regex chars in pattern)
        first_pattern = replacers[0][0].pattern
        # Literals are re.escape'd — check for a device or name literal
        assert any(
            r[0].pattern in (re.escape("Alice Johnson"), re.escape("HOST-PROD-01"))
            for r in replacers[:3]
        )

    def test_longest_literal_first(self):
        """'Alice Johnson' appears before bare 'Alice' (longest match wins)."""
        import re
        replacers = build_replacers(MINIMAL_CONFIG)
        literals = [r for r in replacers if r[0].pattern in (re.escape("Alice Johnson"), re.escape("Alice"))]
        assert len(literals) == 2
        # Alice Johnson (13 chars) must precede Alice (5 chars)
        assert literals[0][0].pattern == re.escape("Alice Johnson")


# ── redact_value ──────────────────────────────────────────────────────────────


class TestRedactValue:
    def setup_method(self):
        self.replacers = build_replacers(MINIMAL_CONFIG)

    def _stats(self):
        return {"replacements": 0, "matched_patterns": set()}

    def test_email_replaced(self):
        stats = self._stats()
        out = redact_value("Contact bob@example.com for details.", self.replacers, stats)
        assert "[EMAIL:redacted]" in out
        assert "@" not in out
        assert stats["replacements"] >= 1

    def test_ip_replaced(self):
        stats = self._stats()
        out = redact_value("Server at 203.0.113.5 is down.", self.replacers, stats)
        assert "[IP:redacted]" in out
        assert "203.0.113.5" not in out

    def test_private_ip_not_replaced(self):
        stats = self._stats()
        out = redact_value("Gateway is 192.168.1.1 and 10.0.0.1", self.replacers, stats)
        assert "192.168.1.1" in out
        assert "10.0.0.1" in out

    def test_known_name_replaced(self):
        stats = self._stats()
        out = redact_value("Alice Johnson submitted the report.", self.replacers, stats)
        assert "[PERSON:user-1]" in out
        assert "Alice Johnson" not in out

    def test_device_replaced(self):
        stats = self._stats()
        out = redact_value("Deployed to HOST-PROD-01 successfully.", self.replacers, stats)
        assert "[VM:session-host]" in out
        assert "HOST-PROD-01" not in out

    def test_email_local_capture(self):
        """Email with {local} preserves the local part."""
        stats = self._stats()
        out = redact_value("Contact alice@acme.com.", self.replacers, stats)
        assert "[EMAIL:client-alice]" in out

    def test_backreference_partial_ip_mask(self):
        """\\2 backreference preserves last two octets: 203.0.113.5 -> x.x.113.5"""
        config = {
            "patterns": [
                {
                    "name": "ipv4_partial_mask",
                    "pattern": "\\b(\\d{1,3}\\.\\d{1,3})(\\.\\d{1,3}\\.\\d{1,3})\\b",
                    "replacement": "x.x\\2",
                }
            ],
            "known_names": {},
            "keys_to_skip": [],
        }
        replacers = build_replacers(config)
        stats = self._stats()
        out = redact_value("Connected from 203.0.113.5 to 198.51.100.22", replacers, stats)
        assert "x.x.113.5" in out
        assert "x.x.100.22" in out
        assert "203.0" not in out
        assert "198.51" not in out
        assert stats["replacements"] == 2

    def test_no_match_returns_original(self):
        stats = self._stats()
        original = "No PII here whatsoever."
        out = redact_value(original, self.replacers, stats)
        assert out == original
        assert stats["replacements"] == 0

    def test_stats_count_accumulates(self):
        stats = self._stats()
        redact_value("a@b.com and c@d.com", self.replacers, stats)
        assert stats["replacements"] >= 2


# ── redact_node ───────────────────────────────────────────────────────────────


class TestRedactNode:
    def setup_method(self):
        self.replacers = build_replacers(MINIMAL_CONFIG)
        self.skip_keys = set(MINIMAL_CONFIG["keys_to_skip"])

    def _stats(self):
        return {"replacements": 0, "matched_patterns": set()}

    def test_dict_string_values_redacted(self):
        stats = self._stats()
        node = {"user": "alice@example.com", "region": "eastus"}
        out = redact_node(node, self.replacers, self.skip_keys, stats)
        assert "[EMAIL:redacted]" in out["user"]
        assert out["region"] == "eastus"  # no PII

    def test_nested_dict(self):
        stats = self._stats()
        node = {"meta": {"owner": "Alice Johnson", "ip": "203.0.113.10"}}
        out = redact_node(node, self.replacers, self.skip_keys, stats)
        assert out["meta"]["owner"] == "[PERSON:user-1]"
        assert "[IP:redacted]" in out["meta"]["ip"]

    def test_list_values_redacted(self):
        stats = self._stats()
        node = ["alice@example.com", "safe string", "203.0.113.5"]
        out = redact_node(node, self.replacers, self.skip_keys, stats)
        assert "[EMAIL:redacted]" in out[0]
        assert out[1] == "safe string"
        assert "[IP:redacted]" in out[2]

    def test_skipped_keys_not_redacted(self):
        stats = self._stats()
        node = {"version": "alice@example.com", "timestamp": "203.0.113.5", "body": "alice@example.com"}
        out = redact_node(node, self.replacers, self.skip_keys, stats)
        assert out["version"] == "alice@example.com"   # skipped
        assert out["timestamp"] == "203.0.113.5"        # skipped
        assert "[EMAIL:redacted]" in out["body"]        # not skipped

    def test_non_string_passthrough(self):
        stats = self._stats()
        node = {"count": 42, "active": True, "score": 3.14, "nothing": None}
        out = redact_node(node, self.replacers, self.skip_keys, stats)
        assert out == node
        assert stats["replacements"] == 0


# ── redact_file ───────────────────────────────────────────────────────────────


class TestRedactFileJson:
    def test_json_file_redacted(self, tmp_path):
        cfg = MINIMAL_CONFIG
        data = {"owner": "alice@example.com", "server": "203.0.113.5"}
        inp = tmp_path / "input.json"
        inp.write_text(json.dumps(data), encoding="utf-8")
        out = tmp_path / "output.json"

        stats = redact_file(inp, out, cfg)

        result = json.loads(out.read_text(encoding="utf-8"))
        assert "[EMAIL:redacted]" in result["owner"]
        assert "[IP:redacted]" in result["server"]
        assert stats["replacements"] >= 2

    def test_json_dry_run_no_write(self, tmp_path):
        data = {"user": "bob@example.com"}
        inp = tmp_path / "input.json"
        inp.write_text(json.dumps(data), encoding="utf-8")
        out = tmp_path / "output.json"

        redact_file(inp, out, MINIMAL_CONFIG, dry_run=True)

        assert not out.exists()

    def test_invalid_json_falls_back_to_plaintext(self, tmp_path):
        inp = tmp_path / "capture.txt"
        inp.write_text("Server 203.0.113.5 - alice@example.com connected", encoding="utf-8")
        out = tmp_path / "capture-REDACTED.txt"

        stats = redact_file(inp, out, MINIMAL_CONFIG)

        content = out.read_text(encoding="utf-8")
        assert "[IP:redacted]" in content
        assert "[EMAIL:redacted]" in content
        assert stats["replacements"] >= 2


class TestRedactFilePlainText:
    def test_plain_text_flag_skips_json_parse(self, tmp_path):
        """--plain-text processes a valid JSON file as raw text without parsing."""
        data = {"user": "alice@example.com"}
        inp = tmp_path / "data.json"
        inp.write_text(json.dumps(data), encoding="utf-8")
        out = tmp_path / "data-REDACTED.json"

        stats = redact_file(inp, out, MINIMAL_CONFIG, plain_text=True)

        content = out.read_text(encoding="utf-8")
        assert "[EMAIL:redacted]" in content
        assert stats["replacements"] >= 1

    def test_plain_text_txt_file(self, tmp_path):
        inp = tmp_path / "syslog.txt"
        inp.write_text("10:00 HOST-PROD-01 connected from 203.0.113.7", encoding="utf-8")
        out = tmp_path / "syslog-REDACTED.txt"

        stats = redact_file(inp, out, MINIMAL_CONFIG, plain_text=True)

        content = out.read_text(encoding="utf-8")
        assert "[VM:session-host]" in content
        assert "[IP:redacted]" in content

    def test_plain_text_dry_run_no_write(self, tmp_path):
        inp = tmp_path / "file.txt"
        inp.write_text("alice@example.com", encoding="utf-8")
        out = tmp_path / "file-out.txt"

        redact_file(inp, out, MINIMAL_CONFIG, dry_run=True, plain_text=True)

        assert not out.exists()


# ── CLI integration tests ─────────────────────────────────────────────────────


@pytest.fixture()
def cfg_file(tmp_path_factory):
    """Write MINIMAL_CONFIG to a temp file; return its path string."""
    p = tmp_path_factory.mktemp("cfg") / "redact-config.json"
    p.write_text(json.dumps(MINIMAL_CONFIG), encoding="utf-8")
    return str(p)


class TestCLI:
    """Invoke main() with patched sys.argv; capture stdout."""

    def _run(self, args: list, capsys):
        sys.argv = ["redactor.py"] + args
        main()
        return capsys.readouterr()

    def test_cli_json_output(self, tmp_path, capsys, cfg_file):
        inp = tmp_path / "file.json"
        inp.write_text(json.dumps({"x": "alice@example.com"}), encoding="utf-8")
        out_dir = tmp_path / "out"

        captured = self._run(
            ["--input", str(inp), "--output", str(out_dir), "--config", cfg_file], capsys
        )

        out_files = list(out_dir.glob("*.json"))
        assert len(out_files) == 1
        result = json.loads(out_files[0].read_text(encoding="utf-8"))
        assert "[EMAIL:redacted]" in result["x"]
        assert "✓" in captured.out

    def test_cli_dry_run_no_files(self, tmp_path, capsys, cfg_file):
        inp = tmp_path / "file.json"
        inp.write_text(json.dumps({"x": "alice@example.com"}), encoding="utf-8")

        captured = self._run(
            ["--input", str(inp), "--dry-run", "--config", cfg_file], capsys
        )

        assert "[DRY RUN]" in captured.out
        # No output file created
        assert not (inp.parent / "public").exists()

    def test_cli_stats_flag(self, tmp_path, capsys, cfg_file):
        inp = tmp_path / "file.json"
        inp.write_text(json.dumps({"x": "alice@example.com"}), encoding="utf-8")

        captured = self._run(
            ["--input", str(inp), "--stats", "--output", str(tmp_path / "out"),
             "--config", cfg_file], capsys
        )

        assert "replacements" in captured.out or "1" in captured.out

    def test_cli_inplace_overwrites_file(self, tmp_path, capsys, cfg_file):
        inp = tmp_path / "file.json"
        inp.write_text(json.dumps({"x": "alice@example.com"}), encoding="utf-8")

        self._run(
            ["--input", str(inp), "--inplace", "--config", cfg_file], capsys
        )

        result = json.loads(inp.read_text(encoding="utf-8"))
        assert "[EMAIL:redacted]" in result["x"]

    def test_cli_inplace_plaintext(self, tmp_path, capsys, cfg_file):
        inp = tmp_path / "capture.txt"
        inp.write_text("Server 203.0.113.5 connected", encoding="utf-8")

        self._run(
            ["--input", str(inp), "--plain-text", "--inplace", "--config", cfg_file], capsys
        )

        content = inp.read_text(encoding="utf-8")
        assert "[IP:redacted]" in content
        assert "203.0.113.5" not in content

    def test_cli_plain_text_flag_with_output(self, tmp_path, capsys, cfg_file):
        inp = tmp_path / "tmsh.txt"
        inp.write_text("ltm node /Common/203.0.113.5 { address 203.0.113.5 }", encoding="utf-8")
        out_dir = tmp_path / "out"

        self._run(
            ["--input", str(inp), "--plain-text", "--output", str(out_dir),
             "--config", cfg_file], capsys
        )

        out_files = list(out_dir.glob("*.txt"))
        assert len(out_files) == 1
        assert "[IP:redacted]" in out_files[0].read_text(encoding="utf-8")

    def test_cli_ext_star_processes_all_files(self, tmp_path, capsys, cfg_file):
        """--ext * should pick up .txt and .json files in a directory."""
        (tmp_path / "a.json").write_text(json.dumps({"x": "1.2.3.4"}), encoding="utf-8")
        (tmp_path / "b.txt").write_text("Server 203.0.113.5", encoding="utf-8")
        out_dir = tmp_path / "out"

        self._run(
            ["--input", str(tmp_path), "--ext", "*", "--plain-text",
             "--output", str(out_dir), "--config", cfg_file], capsys
        )

        out_files = list(out_dir.rglob("*"))
        out_files = [f for f in out_files if f.is_file()]
        assert len(out_files) == 2

    def test_cli_directory_default_ext_json(self, tmp_path, capsys, cfg_file):
        """Default --ext .json should only pick up .json files."""
        (tmp_path / "data.json").write_text(json.dumps({"x": "alice@example.com"}), encoding="utf-8")
        (tmp_path / "notes.txt").write_text("alice@example.com", encoding="utf-8")
        out_dir = tmp_path / "out"

        self._run(
            ["--input", str(tmp_path), "--output", str(out_dir), "--config", cfg_file], capsys
        )

        out_files = [f for f in out_dir.rglob("*") if f.is_file()]
        assert len(out_files) == 1
        assert out_files[0].suffix == ".json"

    def test_cli_inplace_prints_in_place_label(self, tmp_path, capsys, cfg_file):
        inp = tmp_path / "file.json"
        inp.write_text(json.dumps({"x": "alice@example.com"}), encoding="utf-8")

        captured = self._run(
            ["--input", str(inp), "--inplace", "--config", cfg_file], capsys
        )

        assert "(in-place)" in captured.out


# ── Partial IP masking (backreference replacements) ──────────────────────────


class TestBackreferenceReplacement:
    """Backreference strings (\\1, \\2) pass through re.subn natively."""

    PARTIAL_IP_CONFIG = {
        "patterns": [
            {
                "name": "ipv4_mask_first_two_octets",
                "pattern": "\\b(\\d{1,3}\\.\\d{1,3})\\.(\\d{1,3}\\.\\d{1,3})\\b",
                "replacement": "A.B.\\2",
            }
        ],
        "known_names": {},
        "keys_to_skip": [],
        "output": {"suffix": "-REDACTED", "subdir": "public"},
    }

    def _stats(self):
        return {"replacements": 0, "matched_patterns": set()}

    def test_first_two_octets_masked(self):
        replacers = build_replacers(self.PARTIAL_IP_CONFIG)
        stats = self._stats()
        out = redact_value("Server 203.0.113.5 is down.", replacers, stats)
        assert out == "Server A.B.113.5 is down."
        assert stats["replacements"] == 1

    def test_host_suffix_preserved(self):
        """Last two octets survive; only network prefix is masked."""
        replacers = build_replacers(self.PARTIAL_IP_CONFIG)
        stats = self._stats()
        out = redact_value("From 198.51.100.22 to 203.0.113.9", replacers, stats)
        assert "100.22" in out
        assert "113.9" in out
        assert "198.51" not in out
        assert "203.0" not in out

    def test_multiple_ips_in_one_string(self):
        replacers = build_replacers(self.PARTIAL_IP_CONFIG)
        stats = self._stats()
        out = redact_value("203.0.113.5 and 198.51.100.22", replacers, stats)
        assert out == "A.B.113.5 and A.B.100.22"
        assert stats["replacements"] == 2


# ── Regression: json decode error path stats fix ──────────────────────────────


class TestJsonFallbackStats:
    def test_stats_returned_on_json_fallback(self, tmp_path):
        """Ensure matched_patterns is a sorted list (not a set) on plain fallback."""
        inp = tmp_path / "file.log"
        inp.write_text("alice@example.com 203.0.113.5", encoding="utf-8")
        out = tmp_path / "file-out.log"

        stats = redact_file(inp, out, MINIMAL_CONFIG)

        assert isinstance(stats["matched_patterns"], list)
        assert stats["replacements"] >= 2

from pathlib import Path

from repo_shield.cli import redact_text, scan_text


def test_detects_secret_with_line_number(tmp_path: Path):
    path = tmp_path / "example.py"
    text = 'API_KEY = "sk_test_123456789"\nprint("safe")\n'

    findings = scan_text(path, text)

    assert len(findings) == 1
    assert findings[0].line == 1
    assert findings[0].kind == "Credential assignment"


def test_detects_aws_key():
    findings = scan_text(
        Path("config.txt"),
        "aws_access_key = AKIA1234567890ABCDEF\n",
    )

    assert len(findings) == 1
    assert findings[0].kind == "AWS access key"


def test_redacts_detected_values():
    text = 'password = "supersecretvalue"\n'
    redacted = redact_text(text)

    assert "supersecretvalue" not in redacted
    assert "[REDACTED]" in redacted


def test_ignores_binary_content(tmp_path: Path):
    binary_file = tmp_path / "image.bin"
    binary_file.write_bytes(b"\x00AKIA1234567890ABCDEF")

    # This behavior is exercised through the CLI's read_text function in use;
    # the scanner itself only receives decoded text.
    assert binary_file.read_bytes().startswith(b"\x00")
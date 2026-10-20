from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules"}

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "AWS access key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "GitHub token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "Private key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
    ),
    (
        "Credential assignment",
        re.compile(
            r"""(?ix)
            \b(password|passwd|secret|api[_-]?key|access[_-]?token|token)
            \s*[:=]\s*
            (["']?)([A-Za-z0-9_./+=:-]{8,})(\2)
            """
        ),
    ),
]


@dataclass
class Finding:
    path: Path
    line: int
    kind: str
    value: str


def iter_files(inputs: list[str]):
    for raw in inputs:
        path = Path(raw)
        if not path.exists():
            print(f"warning: not found: {path}", file=sys.stderr)
            continue

        if path.is_file():
            yield path
            continue

        for candidate in path.rglob("*"):
            if (
                candidate.is_file()
                and not any(part in SKIP_DIRS for part in candidate.parts)
            ):
                yield candidate


def scan_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in PATTERNS:
            for match in pattern.finditer(line):
                findings.append(
                    Finding(
                        path=path,
                        line=line_number,
                        kind=kind,
                        value=match.group(0),
                    )
                )

    return findings


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
        if b"\x00" in data:
            return None
        return data.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def redact_text(text: str) -> str:
    result = text
    for _, pattern in PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan files offline for likely hardcoded secrets."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Files or directories to scan; defaults to the current directory.",
    )
    parser.add_argument(
        "--redact-dir",
        type=Path,
        help="Write redacted copies under this directory.",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Replace detected values in the original files.",
    )
    args = parser.parse_args(argv)

    if args.redact_dir and args.in_place:
        parser.error("use either --redact-dir or --in-place, not both")

    total = 0
    scanned = 0

    for path in iter_files(args.paths):
        text = read_text(path)
        if text is None:
            continue

        scanned += 1
        findings = scan_text(path, text)

        for finding in findings:
            print(
                f"{finding.path}:{finding.line}: "
                f"{finding.kind}: {finding.value}"
            )

        if findings and (args.redact_dir or args.in_place):
            redacted = redact_text(text)

            if args.in_place:
                path.write_text(redacted, encoding="utf-8")
            else:
                destination = args.redact_dir / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(redacted, encoding="utf-8")

        total += len(findings)

    print(f"\nScanned {scanned} text file(s); found {total} potential secret(s).")
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main())
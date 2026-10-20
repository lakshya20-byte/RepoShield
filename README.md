# RepoShield

RepoShield is a minimal offline Python CLI that scans text files for likely
hardcoded secrets, reports the file and line number, and optionally writes
redacted copies.

It does not send files or findings over the network.

## Requirements

- Python 3.11
- Optional: Docker

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install .
# Greave

Greave is a fast, multi-mode scanner for locating sensitive information in both local filesystems and Confluence pages.

>Part of the **Armour series**  

---

## Overview

Greave is designed for environments where credentials, tokens, and identifiers may be accidentally committed to text files or embedded in documentation.
The scanner provides two distinct modes:

* **Filesystem mode (`fs`)**: recursively walks directories, scanning files that are likely to contain readable text.
* **HTTP mode (`http`)**: connects to Confluence through its REST API, scanning pages, spaces, and optionally historical versions.

In both modes, Greave applies targeted regular expressions to detect identifiers, long random passwords, and password-related keywords. When suspicious combinations are found, the tool records the findings with surrounding context for later review.

---

## Features

* Two scanning modes: filesystem and Confluence API.
* Multi-threaded workers for fast scanning.
* Configurable parameters: worker count, retries, backoff, context length, maximum file size, and more.
* Deduplicated results to avoid repetition.
* Outputs in both CSV and NDJSON formats.
* Optional scanning of historical Confluence versions.
* Lightweight: only uses the Python standard library.

---

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/greycloudss/Greave.git
cd Greave
```

Greave requires Python 3.8 or later. It has no external dependencies.

---

## Usage

### Filesystem Mode

```bash
python greave.py \
  --mode fs \
  --root /path/to/scan \
  --workers 24 \
  --csv results_fs.csv \
  --ndjson results_fs.ndjson
```

Useful options:

* `--include-ext` / `--exclude-ext`: filter file extensions.
* `--max-bytes`: limit bytes read per file.
* `--follow-symlinks`: traverse symlinked directories.

---

### HTTP Mode (Confluence)

```bash
python greave.py \
  --mode http \
  --base-url https://example.atlassian.net/wiki \
  --email user@example.com \
  --api-token <token> \
  --workers 16 \
  --include-history \
  --csv results_http.csv \
  --ndjson results_http.ndjson
```

Useful options:

* `--space`: restrict scan to a space key.
* `--max-versions`: control historical versions scanned.
* `--auth`: select authentication method (`auto`, `basic`, `bearer`).

---

## Output

Results are written in two formats:

* **CSV**: for quick inspection or spreadsheet analysis.
* **NDJSON**: newline-delimited JSON, ideal for automated ingestion.

Each record contains:
`space`, `page_id`, `page_title`, `version`, `version_when`,
`match_type`, `id_value`, `id_literal`, `password_value`,
`context`, `url`

---

## Threat Model

Greave is designed to detect accidental exposure of secrets in human-readable text. It is effective against:

* Long random passwords embedded in files or documentation.
* Identifiers (such as service request numbers) near password keywords.

It does not protect against:

* Encrypted or binary data leaks.
* Secrets stored in compiled artifacts or non-text formats.
* Active network threats or credential misuse once exposed.

Greave is intended as a preventative and auditing tool, not as a replacement for proper access controls or secret management systems.

---

## License

Greave is released under the MIT License. See the LICENSE file for details.

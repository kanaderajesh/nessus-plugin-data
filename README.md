# Tenable Security Center Plugin Data

A Python 3.12 command-line tool that downloads plugin data from the
[Tenable Security Center](https://www.tenable.com/products/security-center)
REST API and writes it to a CSV file.

---

## Table of contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Usage](#usage)
   - [Bulk mode](#bulk-mode)
   - [ID-list mode](#id-list-mode)
4. [Authentication](#authentication)
5. [Options reference](#options-reference)
6. [Fields](#fields)
7. [How it works](#how-it-works)
8. [Files](#files)

---

## Requirements

- Python **3.12+**
- `requests` 2.32.3+
- `urllib3` 2.2.2+
- `certifi` 2024.7.4+

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/kanaderajesh/nessus-plugin-data.git
cd nessus-plugin-data

# 2. Create and activate a virtual environment
python3.12 -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

The tool operates in two modes depending on whether `--input-csv` is provided.

```
usage: tenable_sc_fetch [-h]
                        --host HOST [--no-verify]
                        [-u USER] [-p PASS]
                        [--access-key AK] [--secret-key SK]
                        [-o FILE] [--fields FIELDS]
                        [--batch-size N] [--max-plugins N]
                        [-i FILE] [--id-column COL] [--workers N]
```

---

### Bulk mode

Fetches **every** plugin from Tenable SC by paginating `GET /rest/plugin`
and writes the results to a CSV file.

#### Minimal — username / password

```bash
python tenable_sc_fetch.py --host sc.example.com -u admin -p secret
```

#### Minimal — API key pair (SC 5.13+)

```bash
python tenable_sc_fetch.py --host sc.example.com \
    --access-key YOUR_ACCESS_KEY \
    --secret-key YOUR_SECRET_KEY
```

#### Specify output file and fields

```bash
python tenable_sc_fetch.py \
    --host sc.example.com -u admin -p secret \
    --output all_plugins.csv \
    --fields id,name,severity,family,cvssV3BaseScore,exploitable,description
```

#### Limit the number of plugins downloaded

```bash
python tenable_sc_fetch.py \
    --host sc.example.com -u admin -p secret \
    --max-plugins 500
```

#### Increase page size for faster downloads

```bash
python tenable_sc_fetch.py \
    --host sc.example.com -u admin -p secret \
    --batch-size 2000
```

#### Disable SSL verification (self-signed certificate)

```bash
python tenable_sc_fetch.py \
    --host sc.example.com -u admin -p secret \
    --no-verify
```

**Expected output:**

```
[+] Authenticating as 'admin' on sc.example.com ...
[+] Authenticated via session token.
[+] Fetching all plugins from https://sc.example.com/rest/plugin ...
  Total plugins: 83,241  |  batch size: 1,000
  [█████████████████████████████████████████████] 83,241/83,241  (100.0%)
[+] Writing 83,241 rows → 'plugins_20260603_120000.csv' ...
[+] Done.  83,241 plugins saved to 'plugins_20260603_120000.csv' (142.7 KB, 34.2s).
```

---

### ID-list mode

Reads plugin IDs from a CSV file and calls `GET /rest/plugin/{id}` for each
one. The `--fields` value is passed directly as `?fields=...` on every
request. Fetches run concurrently for speed.

Activated by passing `--input-csv` (or `-i`).

#### Prepare an input CSV

The file needs one column that contains the plugin IDs. The default column
name is `id`; use `--id-column` to specify a different one.

```csv
id,notes
10863,SSL certificate information
19506,Nessus scan metadata
11936,OS identification
```

#### Fetch with all available fields (dynamic header discovery)

When `--fields` is omitted, the tool writes every field returned by the API
and builds the CSV header automatically from the responses.

```bash
python tenable_sc_fetch.py \
    --host sc.example.com -u admin -p secret \
    --input-csv plugin_ids.csv
```

#### Fetch with explicit fields

```bash
python tenable_sc_fetch.py \
    --host sc.example.com -u admin -p secret \
    --input-csv plugin_ids.csv \
    --fields id,name,severity,family,cvssV3BaseScore,exploitable,description
```

#### Use a different ID column name

```bash
python tenable_sc_fetch.py \
    --host sc.example.com -u admin -p secret \
    --input-csv report.csv \
    --id-column plugin_id
```

#### Increase concurrent workers for large ID lists

```bash
python tenable_sc_fetch.py \
    --host sc.example.com -u admin -p secret \
    --input-csv plugin_ids.csv \
    --workers 10
```

#### Specify a custom output file

```bash
python tenable_sc_fetch.py \
    --host sc.example.com -u admin -p secret \
    --input-csv plugin_ids.csv \
    --output selected_plugins.csv
```

**Expected output:**

```
[+] Authenticating as 'admin' on sc.example.com ...
[+] Authenticated via session token.
[+] Reading plugin IDs from 'plugin_ids.csv' (column: 'id') ...
[+] Found 3 plugin ID(s).
[+] Fetching from https://sc.example.com/rest/plugin/{id} with fields=(all fields) ...
  Plugin IDs to fetch: 3  |  workers: 5
  [█████████████████████████████████████████████] 3/3  (100.0%)
  Discovered 24 field(s) from API responses.
[+] Writing 3 rows → 'selected_plugins.csv' ...
[+] Done.  3 plugins saved to 'selected_plugins.csv' (1.2 KB, 0.3s).
```

---

## Authentication

Credentials can be supplied as **CLI flags** or **environment variables**.
CLI flags take precedence when both are provided.

| Env var | CLI flag | Description |
|---|---|---|
| `TSC_HOST` | `--host` | Tenable SC hostname or URL |
| `TSC_USERNAME` | `-u / --username` | Username |
| `TSC_PASSWORD` | `-p / --password` | Password |
| `TSC_ACCESS_KEY` | `--access-key` | API access key (SC 5.13+) |
| `TSC_SECRET_KEY` | `--secret-key` | API secret key (SC 5.13+) |

### Via environment variables

Using env vars keeps credentials out of shell history and process listings.

```bash
# Username / password
export TSC_HOST=sc.example.com
export TSC_USERNAME=admin
export TSC_PASSWORD=secret
python tenable_sc_fetch.py

# API key pair
export TSC_HOST=sc.example.com
export TSC_ACCESS_KEY=YOUR_ACCESS_KEY
export TSC_SECRET_KEY=YOUR_SECRET_KEY
python tenable_sc_fetch.py
```

### Via a .env file

```bash
# .env  (add to .gitignore — never commit credentials)
TSC_HOST=sc.example.com
TSC_USERNAME=admin
TSC_PASSWORD=secret
```

```bash
set -a && source .env && set +a
python tenable_sc_fetch.py
```

---

## Options reference

### Connection

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--host HOST` | `TSC_HOST` | — | Tenable SC hostname or full URL (**required**) |
| `--no-verify` | — | off | Skip SSL certificate verification |

### Username / password authentication

| Flag | Env var | Default | Description |
|---|---|---|---|
| `-u / --username USER` | `TSC_USERNAME` | — | Username |
| `-p / --password PASS` | `TSC_PASSWORD` | — | Password |

### API key authentication (SC 5.13+)

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--access-key AK` | `TSC_ACCESS_KEY` | — | API access key |
| `--secret-key SK` | `TSC_SECRET_KEY` | — | API secret key |

### Output

| Flag | Default | Description |
|---|---|---|
| `-o / --output FILE` | `plugins_YYYYMMDD_HHMMSS.csv` | Output CSV path |
| `--fields FIELDS` | *(see [Fields](#fields))* | Comma-separated API field names |

### Bulk mode options

| Flag | Default | Description |
|---|---|---|
| `--batch-size N` | `1000` | Plugins per API page |
| `--max-plugins N` | all | Stop after N plugins |

### ID-list mode options

| Flag | Default | Description |
|---|---|---|
| `-i / --input-csv FILE` | — | Input CSV with plugin IDs (activates ID-list mode) |
| `--id-column COL` | `id` | Column in input CSV that holds the plugin IDs |
| `--workers N` | `5` | Concurrent HTTP workers |

---

## Fields

Pass `--fields` as a comma-separated list to control which fields are
requested from the API **and** written as columns in the output CSV.

```bash
--fields id,name,severity,family,cvssV3BaseScore,exploitable,description
```

### Bulk mode default fields

When `--fields` is omitted in bulk mode, these 19 fields are used:

```
id                    name                  version
type                  severity              family
modifiedTime          publicationDate       patchPublicationDate
vulnPublicationDate   exploitable           cvssVector
baseScore             temporalScore         cvssV3Vector
cvssV3BaseScore       checkType             description
copyright
```

### ID-list mode — dynamic fields

When `--fields` is omitted in ID-list mode, the tool requests all fields
from the API and discovers the CSV columns from the actual responses.
Different plugins may return different fields; the tool unions all keys
across every response to form the final header.

### Nested object flattening

Fields that return objects (e.g. `severity`, `family`) are automatically
flattened to their `name` value so the CSV stays importable in Excel,
pandas, and other tools.

| API response | CSV value |
|---|---|
| `{"id": "2", "name": "Medium"}` | `Medium` |
| `{"id": "3", "name": "Web Servers"}` | `Web Servers` |
| `["CVE-2024-1234", "CVE-2024-5678"]` | `CVE-2024-1234; CVE-2024-5678` |

---

## How it works

### Bulk mode

1. **Authenticate** — `POST /rest/token` (session token) or `X-APIKey` header (API keys).
2. **Count** — probes `GET /rest/plugin?startOffset=0&endOffset=1` to read `usableCount`.
3. **Paginate** — loops `GET /rest/plugin?fields=...&startOffset=N&endOffset=M` until done.
4. **Retry** — HTTP 500/502/503/504 responses are retried up to 4 times with exponential back-off.
5. **Write** — all rows are flattened and written to a UTF-8 CSV with a header row.
6. **Logout** — `DELETE /rest/token` (no-op for API key auth).

### ID-list mode

1. **Authenticate** — same as above.
2. **Read IDs** — parses `--id-column` from `--input-csv`.
3. **Fetch concurrently** — a `ThreadPoolExecutor` calls `GET /rest/plugin/{id}?fields=...`
   for every ID using `--workers` threads in parallel.
4. **Skip failures** — HTTP errors on individual IDs are printed as warnings and
   skipped; they do not abort the run.
5. **Discover header** — when `--fields` is not set, the union of all response
   keys becomes the CSV header.
6. **Write** — same as bulk mode.
7. **Logout** — same as bulk mode.

---

## Files

```
.
├── tenable_sc_fetch.py   # CLI application
├── requirements.txt      # Python 3.12 pinned dependencies
└── README.md             # This file
```

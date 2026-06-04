# Tenable Security Center Plugin Data

A command-line tool that downloads plugin data from the
[Tenable Security Center](https://www.tenable.com/products/security-center)
REST API and writes it to a CSV file.

## Requirements

- **Python 3.12+**
- [`requests`](https://pypi.org/project/requests/) 2.32.3+
- [`urllib3`](https://pypi.org/project/urllib3/) 2.2.2+
- [`certifi`](https://pypi.org/project/certifi/) 2024.7.4+

```bash
# Create and activate a virtual environment
python3.12 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Modes

### Bulk mode *(default)*

Paginates through **all** plugins via `GET /rest/plugin` and writes every
record to a CSV. Good for a full one-time export.

```bash
python tenable_sc_fetch.py --host sc.example.com -u admin -p secret
```

### ID-list mode *(activated by `--input-csv`)*

Reads plugin IDs from a CSV file and calls `GET /rest/plugin/{id}` for
each one. Good for fetching a curated subset with richer per-plugin detail.

```bash
# plugin_ids.csv must contain a column named "id" (configurable via --id-column)
python tenable_sc_fetch.py --host sc.example.com -u admin -p secret \
    --input-csv plugin_ids.csv
```

Example `plugin_ids.csv`:

```csv
id,notes
10863,SSL cert info
19506,Scan metadata
11936,OS identification
```

---

## Authentication

Credentials can be provided as **CLI flags** or **environment variables**.
CLI flags take precedence when both are set.

| Env var | CLI flag | Description |
|---|---|---|
| `TSC_HOST` | `--host` | Tenable SC hostname or URL |
| `TSC_USERNAME` | `-u / --username` | Username |
| `TSC_PASSWORD` | `-p / --password` | Password |
| `TSC_ACCESS_KEY` | `--access-key` | API access key (SC 5.13+) |
| `TSC_SECRET_KEY` | `--secret-key` | API secret key (SC 5.13+) |

### Username / password — flags

```bash
python tenable_sc_fetch.py --host sc.example.com -u admin -p secret
```

### Username / password — environment variables

```bash
export TSC_HOST=sc.example.com
export TSC_USERNAME=admin
export TSC_PASSWORD=secret
python tenable_sc_fetch.py
```

### API key pair — flags (SC 5.13+)

```bash
python tenable_sc_fetch.py --host sc.example.com \
    --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY
```

### API key pair — environment variables

```bash
export TSC_HOST=sc.example.com
export TSC_ACCESS_KEY=YOUR_ACCESS_KEY
export TSC_SECRET_KEY=YOUR_SECRET_KEY
python tenable_sc_fetch.py
```

> **Tip:** Store credentials in a `.env` file and source it:
> ```bash
> set -a && source .env && set +a
> python tenable_sc_fetch.py
> ```
> Add `.env` to `.gitignore` to keep credentials out of version control.

---

## All options

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--host HOST` | `TSC_HOST` | — | Tenable SC hostname or full URL (**required**) |
| `--no-verify` | — | off | Disable SSL certificate verification |
| `-u / --username USER` | `TSC_USERNAME` | — | Username for session auth |
| `-p / --password PASS` | `TSC_PASSWORD` | — | Password for session auth |
| `--access-key AK` | `TSC_ACCESS_KEY` | — | API access key (SC 5.13+) |
| `--secret-key SK` | `TSC_SECRET_KEY` | — | API secret key (SC 5.13+) |
| `-o / --output FILE` | — | `plugins_YYYYMMDD_HHMMSS.csv` | Output CSV path |
| `--fields FIELDS` | — | *(see below)* | Comma-separated API fields |
| `--batch-size N` | — | `1000` | Plugins per bulk API request |
| `--max-plugins N` | — | all | Cap total plugins in bulk mode |
| `-i / --input-csv FILE` | — | — | Input CSV with plugin IDs (activates ID-list mode) |
| `--id-column COL` | — | `id` | Column in `--input-csv` that holds plugin IDs |
| `--workers N` | — | `5` | Concurrent HTTP workers in ID-list mode |

---

## Fields

Pass `--fields` as a comma-separated list to control which API fields are
requested **and** written to the output CSV.

```bash
python tenable_sc_fetch.py --host sc.example.com -u admin -p secret \
    --input-csv ids.csv \
    --fields id,name,severity,family,cvssV3BaseScore,exploitable,description
```

### Bulk mode default (when `--fields` is omitted)

```
id, name, version, type, severity, family,
modifiedTime, publicationDate, patchPublicationDate, vulnPublicationDate,
exploitable, cvssVector, baseScore, temporalScore,
cvssV3Vector, cvssV3BaseScore, checkType, description, copyright
```

### ID-list mode default (when `--fields` is omitted)

All fields returned by each `GET /rest/plugin/{id}` response are written.
Column names are discovered automatically from the responses — different
plugins may return different fields, so the tool unions all keys across
every response to build the CSV header.

Nested objects (e.g. `severity`, `family`) are flattened to their `name`
value (e.g. `"Medium"`, `"Web Servers"`).

---

## How it works

### Bulk mode

1. **Authenticate** via `POST /rest/token` or `X-APIKey` header.
2. **Count** — probes `GET /rest/plugin?startOffset=0&endOffset=1` to read `usableCount`.
3. **Paginate** — loops `GET /rest/plugin?fields=...&startOffset=N&endOffset=M` with retry on 5xx errors.
4. **Write** — flattens records and streams to a UTF-8 CSV.
5. **Logout** — `DELETE /rest/token` (no-op for API key auth).

### ID-list mode

1. **Authenticate** (same as above).
2. **Read IDs** — parses the `--id-column` column from `--input-csv`.
3. **Fetch concurrently** — a `ThreadPoolExecutor` with `--workers` threads
   calls `GET /rest/plugin/{id}?fields=...` for each ID.  Individual
   HTTP errors are logged as warnings and skipped — they do not abort the run.
4. **Discover header** — if `--fields` was not given, the union of all
   response keys is used as the CSV header.
5. **Write** — same as bulk mode.
6. **Logout** — same as bulk mode.

---

## Example terminal output

### Bulk mode

```
[+] Authenticating as 'admin' on sc.example.com ...
[+] Authenticated via session token.
[+] Fetching all plugins from https://sc.example.com/rest/plugin ...
  Total plugins: 83,241  |  batch size: 1,000
  [█████████████████████████████████████████████] 83,241/83,241  (100.0%)
[+] Writing 83,241 rows → 'plugins_20260603_120000.csv' ...
[+] Done.  83,241 plugins saved to 'plugins_20260603_120000.csv' (142.7 KB, 34.2s).
```

### ID-list mode

```
[+] Authenticating as 'admin' on sc.example.com ...
[+] Authenticated via session token.
[+] Reading plugin IDs from 'plugin_ids.csv' (column: 'id') ...
[+] Found 3 plugin ID(s).
[+] Fetching from https://sc.example.com/rest/plugin/{id} with fields=(all fields) ...
  Plugin IDs to fetch: 3  |  workers: 5
  [█████████████████████████████████████████████] 3/3  (100.0%)
  Discovered 24 field(s) from API responses.
[+] Writing 3 rows → 'plugins_20260603_120005.csv' ...
[+] Done.  3 plugins saved to 'plugins_20260603_120005.csv' (1.2 KB, 0.3s).
```

---

## Files

```
.
├── tenable_sc_fetch.py   # CLI tool
├── requirements.txt      # Python 3.12 pinned dependencies
└── README.md
```

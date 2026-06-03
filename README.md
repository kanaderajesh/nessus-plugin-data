# Tenable Security Center Plugin Data

A command-line tool that downloads all plugin data from the
[Tenable Security Center](https://www.tenable.com/products/security-center)
REST API and writes it to a CSV file.

## Requirements

- **Python 3.12+**
- [`requests`](https://pypi.org/project/requests/) 2.32.3+
- [`urllib3`](https://pypi.org/project/urllib3/) 2.2.2+
- [`certifi`](https://pypi.org/project/certifi/) 2024.7.4+

### Install dependencies

```bash
# Create and activate a virtual environment (recommended)
python3.12 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

## Quick start

```bash
# Username / password
python tenable_sc_fetch.py --host sc.example.com -u admin -p secret

# API key pair (Tenable SC 5.13+)
python tenable_sc_fetch.py --host sc.example.com \
    --access-key YOUR_ACCESS_KEY \
    --secret-key YOUR_SECRET_KEY
```

## Credentials via environment variables

Passing credentials as CLI flags exposes them in shell history and process
listings. Use environment variables instead:

| Environment variable | Replaces flag |
|---|---|
| `TSC_HOST` | `--host` |
| `TSC_USERNAME` | `-u / --username` |
| `TSC_PASSWORD` | `-p / --password` |
| `TSC_ACCESS_KEY` | `--access-key` |
| `TSC_SECRET_KEY` | `--secret-key` |

CLI flags always take precedence over environment variables when both are set.

### Example — username / password via env vars

```bash
export TSC_HOST=sc.example.com
export TSC_USERNAME=admin
export TSC_PASSWORD=secret

python tenable_sc_fetch.py
```

### Example — API key pair via env vars

```bash
export TSC_HOST=sc.example.com
export TSC_ACCESS_KEY=YOUR_ACCESS_KEY
export TSC_SECRET_KEY=YOUR_SECRET_KEY

python tenable_sc_fetch.py
```

### Example — using a .env file

```bash
# .env (keep out of version control)
TSC_HOST=sc.example.com
TSC_USERNAME=admin
TSC_PASSWORD=secret
```

```bash
set -a && source .env && set +a
python tenable_sc_fetch.py
```

> **Tip:** Add `.env` to your `.gitignore` so credentials are never committed.

## Full usage

```
usage: tenable_sc_fetch [-h] --host HOST [--no-verify]
                        [-u USER] [-p PASS]
                        [--access-key ACCESS_KEY] [--secret-key SECRET_KEY]
                        [-o FILE] [--fields FIELDS]
                        [--batch-size N] [--max-plugins N]
```

### All options

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--host HOST` | `TSC_HOST` | — | Tenable SC hostname or full URL (**required**) |
| `--no-verify` | — | off | Disable SSL certificate verification |
| `-u / --username USER` | `TSC_USERNAME` | — | Username for session-based auth |
| `-p / --password PASS` | `TSC_PASSWORD` | — | Password for session-based auth |
| `--access-key ACCESS_KEY` | `TSC_ACCESS_KEY` | — | API access key (SC 5.13+) |
| `--secret-key SECRET_KEY` | `TSC_SECRET_KEY` | — | API secret key (SC 5.13+) |
| `-o / --output FILE` | — | `plugins_YYYYMMDD_HHMMSS.csv` | Output CSV path |
| `--fields FIELDS` | — | *(see below)* | Comma-separated API fields to include |
| `--batch-size N` | — | `1000` | Plugins fetched per API request |
| `--max-plugins N` | — | all | Stop after downloading N plugins |

### Default CSV fields

```
id, name, version, type, severity, family,
modifiedTime, publicationDate, patchPublicationDate, vulnPublicationDate,
exploitable, cvssVector, baseScore, temporalScore,
cvssV3Vector, cvssV3BaseScore, checkType, description, copyright
```

Nested objects such as `severity` and `family` are automatically flattened
to their `name` value (e.g. `"Medium"`, `"Web Servers"`).

### Custom field list example

```bash
python tenable_sc_fetch.py \
    --host sc.example.com -u admin -p secret \
    --output plugins.csv \
    --fields id,name,severity,family,cvssV3BaseScore,exploitable,description
```

### Self-signed certificate

```bash
python tenable_sc_fetch.py --host sc.example.com -u admin -p secret --no-verify
```

## How it works

1. **Authenticate** — POSTs credentials to `POST /rest/token` (session token)
   or adds an `X-APIKey` header (API key pair).
2. **Count** — issues a minimal `GET /rest/plugin?startOffset=0&endOffset=1`
   to read `usableCount` from the response.
3. **Paginate** — loops through `GET /rest/plugin?startOffset=N&endOffset=M`
   with automatic retry on transient HTTP 500/502/503/504 errors, printing a
   live progress bar.
4. **Flatten** — converts every nested API value to a plain string so the
   CSV remains importable in Excel, pandas, etc.
5. **Write** — streams all rows into a UTF-8 CSV file with a header row.
6. **Logout** — sends `DELETE /rest/token` to invalidate the session
   (no-op for API key auth).

## Example terminal output

```
[+] Authenticating as 'admin' on sc.example.com ...
[+] Authenticated via session token.
[+] Fetching plugins from https://sc.example.com/rest/plugin ...
  Total plugins: 83,241  |  batch size: 1,000
  [█████████████████████████████████████████████] 83,241/83,241  (100.0%)
[+] Writing 83,241 rows -> 'plugins_20260603_120000.csv' ...
[+] Done.  83,241 plugins saved to 'plugins_20260603_120000.csv' (142.7 KB, 34.2s).
```

## Files

```
.
├── tenable_sc_fetch.py   # CLI tool
├── requirements.txt      # Python 3.12 dependencies
└── README.md
```

## Authentication methods

### Session token (username / password)

Calls `POST /rest/token` and stores the returned token in the
`X-SecurityCenter` request header for all subsequent calls.
The token is revoked on exit via `DELETE /rest/token`.

### API key pair (Tenable SC 5.13+)

Sends `X-APIKey: accesskey=<AK>; secretkey=<SK>` on every request.
No session is created or destroyed.

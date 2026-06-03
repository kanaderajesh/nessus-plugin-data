# Tenable Security Center Plugin Data

A command-line tool that downloads all plugin data from the
[Tenable Security Center](https://www.tenable.com/products/security-center)
REST API and writes it to a CSV file.

## Requirements

- Python 3.10+
- `requests`

```bash
pip install -r requirements.txt
```

## Usage

### Username / password authentication

```bash
python tenable_sc_fetch.py --host sc.example.com -u admin -p secret
```

### API key authentication (Tenable SC 5.13+)

```bash
python tenable_sc_fetch.py --host sc.example.com \
    --access-key YOUR_ACCESS_KEY \
    --secret-key YOUR_SECRET_KEY
```

### Full example with options

```bash
python tenable_sc_fetch.py \
    --host sc.example.com \
    -u admin -p secret \
    --output plugins.csv \
    --fields id,name,severity,family,cvssV3BaseScore,description \
    --batch-size 500 \
    --no-verify
```

## Options

| Flag | Description |
|---|---|
| `--host HOST` | Tenable SC hostname or full URL (**required**) |
| `-u / --username` | Username for session-based auth |
| `-p / --password` | Password for session-based auth |
| `--access-key` | API access key (SC 5.13+) |
| `--secret-key` | API secret key (SC 5.13+) |
| `-o / --output FILE` | Output CSV path (default: `plugins_YYYYMMDD_HHMMSS.csv`) |
| `--fields FIELDS` | Comma-separated list of API fields to include |
| `--batch-size N` | Plugins per API request (default: 1000) |
| `--max-plugins N` | Stop after N plugins (default: all) |
| `--no-verify` | Disable SSL certificate verification |

## Default CSV fields

```
id, name, version, type, severity, family,
modifiedTime, publicationDate, patchPublicationDate, vulnPublicationDate,
exploitable, cvssVector, baseScore, temporalScore,
cvssV3Vector, cvssV3BaseScore, checkType, description, copyright
```

Nested objects (e.g. `severity`, `family`) are flattened to their `name` value.

## How it works

1. **Authenticate** — either POSTs to `/rest/token` (session) or sends
   an `X-APIKey` header (API keys).
2. **Count** — fetches a single record to read `usableCount` from the response.
3. **Paginate** — loops through `GET /rest/plugin?startOffset=N&endOffset=M`
   until all plugins are retrieved, showing a live progress bar.
4. **Write** — flattens every record to a plain string and streams them into
   a UTF-8 CSV file.
5. **Logout** — invalidates the session token (no-op for API key auth).

## Example output

```
[+] Authenticating as 'admin' on sc.example.com ...
[+] Authenticated via session token.
[+] Fetching plugins from https://sc.example.com/rest/plugin ...
  Total plugins: 83,241  |  batch size: 1,000
  [█████████████████████████████████████████████] 83,241/83,241  (100.0%)
[+] Writing 83,241 rows -> 'plugins_20260603_120000.csv' ...
[+] Done.  83,241 plugins saved to 'plugins_20260603_120000.csv' (142.7 KB, 34.2s).
```

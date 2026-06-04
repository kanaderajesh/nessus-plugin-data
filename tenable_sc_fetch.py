#!/usr/bin/env python3
"""
tenable_sc_fetch.py
===================
Downloads Tenable Security Center plugin data to a CSV file.

Two modes of operation
----------------------
Bulk mode (default)
    Paginates through all plugins via GET /rest/plugin and writes every
    record to a CSV.  Use --batch-size and --max-plugins to tune the run.

ID-list mode  (activated by --input-csv)
    Reads plugin IDs from a CSV file and calls GET /rest/plugin/{id} for
    each one.  Supports concurrent fetching via --workers.  When --fields
    is omitted the full API response is written and column names are
    discovered dynamically from the responses.

Authentication
--------------
Supply credentials via CLI flags OR environment variables:

  Environment variable  CLI flag
  --------------------  --------
  TSC_HOST              --host
  TSC_USERNAME          -u / --username
  TSC_PASSWORD          -p / --password
  TSC_ACCESS_KEY        --access-key
  TSC_SECRET_KEY        --secret-key

CLI flags take precedence when both are set.

Usage examples
--------------
  # Bulk download (all plugins):
  python tenable_sc_fetch.py --host sc.example.com -u admin -p secret

  # Bulk download via env vars:
  export TSC_HOST=sc.example.com TSC_USERNAME=admin TSC_PASSWORD=secret
  python tenable_sc_fetch.py

  # ID-list mode (fetch specific plugins):
  python tenable_sc_fetch.py --host sc.example.com -u admin -p secret \\
      --input-csv plugin_ids.csv --id-column plugin_id

  # ID-list mode with explicit fields:
  python tenable_sc_fetch.py --host sc.example.com -u admin -p secret \\
      --input-csv plugin_ids.csv \\
      --fields id,name,severity,family,cvssV3BaseScore,description

  # API key pair:
  python tenable_sc_fetch.py --host sc.example.com \\
      --access-key AK --secret-key SK --input-csv ids.csv

  # Disable SSL verification (self-signed cert):
  python tenable_sc_fetch.py --host sc.example.com -u admin -p secret --no-verify
"""

import argparse
import concurrent.futures
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("[ERROR] 'requests' is required.  Install it with:  pip install requests")

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_FIELDS: list[str] = [
    "id", "name", "version", "type",
    "severity", "family",
    "modifiedTime", "publicationDate", "patchPublicationDate", "vulnPublicationDate",
    "exploitable",
    "cvssVector", "baseScore", "temporalScore",
    "cvssV3Vector", "cvssV3BaseScore",
    "checkType", "description", "copyright",
]

DEFAULT_BATCH_SIZE: int = 1000
DEFAULT_WORKERS: int = 5


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class TenableSCError(Exception):
    """Raised for recoverable per-item HTTP errors in ID-list mode."""


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _build_session(verify_ssl: bool) -> requests.Session:
    session = requests.Session()
    session.verify = verify_ssl
    session.headers.update({
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    retry = Retry(
        total=4,
        backoff_factor=2,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST", "DELETE"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------

class TenableSCClient:
    """Thin wrapper around the Tenable Security Center REST API."""

    def __init__(self, host: str, verify_ssl: bool = True) -> None:
        host = host.rstrip("/")
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        self.base_url = f"{host}/rest"
        self.session = _build_session(verify_ssl)
        self._using_token = False

    # -- authentication -------------------------------------------------------

    def login(self, username: str, password: str) -> None:
        """Authenticate with username / password and store the session token."""
        resp = self.session.post(
            f"{self.base_url}/token",
            json={"username": username, "password": password},
        )
        _fatal_for_status(resp, "Login failed")
        token = resp.json().get("response", {}).get("token")
        if not token:
            sys.exit(
                f"[ERROR] No token in login response:\n"
                f"{json.dumps(resp.json(), indent=2)}"
            )
        self.session.headers["X-SecurityCenter"] = token
        self._using_token = True

    def set_api_keys(self, access_key: str, secret_key: str) -> None:
        """Configure API key authentication (Tenable SC 5.13+)."""
        self.session.headers["X-APIKey"] = (
            f"accesskey={access_key}; secretkey={secret_key}"
        )

    def logout(self) -> None:
        """Invalidate the session token (no-op for API key auth)."""
        if not self._using_token:
            return
        try:
            self.session.delete(f"{self.base_url}/token")
        except Exception:
            pass

    # -- bulk plugin list -----------------------------------------------------

    def get_plugin_page(
        self,
        fields: list[str],
        start: int,
        count: int,
    ) -> dict:
        """Fetch one page of plugins via GET /rest/plugin."""
        params: dict[str, Any] = {
            "fields": ",".join(fields),
            "startOffset": start,
            "endOffset": start + count,
        }
        resp = self.session.get(f"{self.base_url}/plugin", params=params)
        _fatal_for_status(resp, f"Failed to fetch plugins at offset {start}")
        return resp.json()

    def get_total_plugin_count(self) -> int:
        """Return the total plugin count from a minimal API probe."""
        data = self.get_plugin_page(fields=["id"], start=0, count=1)
        return int(data.get("response", {}).get("usableCount", 0))

    # -- single plugin by ID --------------------------------------------------

    def get_plugin_by_id(
        self,
        plugin_id: str,
        fields: list[str] | None = None,
    ) -> dict:
        """
        Fetch a single plugin via GET /rest/plugin/{id}.

        Parameters
        ----------
        plugin_id:
            Numeric plugin ID string.
        fields:
            Optional list of field names to request.  When None the API
            returns all available fields for that plugin.

        Raises
        ------
        TenableSCError
            On any HTTP error so the caller can decide whether to skip or abort.
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = ",".join(fields)
        resp = self.session.get(
            f"{self.base_url}/plugin/{plugin_id}",
            params=params,
        )
        _raise_for_status(resp, f"Plugin {plugin_id}")
        return resp.json()


# ---------------------------------------------------------------------------
# HTTP error helpers
# ---------------------------------------------------------------------------

def _fatal_for_status(resp: requests.Response, context: str) -> None:
    """Call sys.exit on HTTP error — used for auth and bulk operations."""
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("error_msg", resp.text[:400])
        except Exception:
            detail = resp.text[:400]
        sys.exit(f"[ERROR] {context}: HTTP {resp.status_code} — {detail}")


def _raise_for_status(resp: requests.Response, context: str) -> None:
    """Raise TenableSCError on HTTP error — used for per-ID operations."""
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("error_msg", resp.text[:200])
        except Exception:
            detail = resp.text[:200]
        raise TenableSCError(f"{context}: HTTP {resp.status_code} — {detail}")


# ---------------------------------------------------------------------------
# Value flattening
# ---------------------------------------------------------------------------

def _flatten_value(value: Any) -> str:
    """Convert any API value (dict, list, scalar, None) to a plain string."""
    if value is None:
        return ""
    if isinstance(value, dict):
        # Tenable SC: {"id": "2", "name": "Medium", ...} -> "Medium"
        if "name" in value:
            return str(value["name"])
        return "; ".join(str(v) for v in value.values() if v is not None)
    if isinstance(value, list):
        return "; ".join(_flatten_value(item) for item in value)
    return str(value)


def _flatten_plugin(plugin: dict, fields: list[str]) -> dict[str, str]:
    return {field: _flatten_value(plugin.get(field)) for field in fields}


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

def _progress_line(current: int, total: int, bar_width: int = 45) -> str:
    pct = current / total if total else 0
    filled = int(bar_width * pct)
    bar = "█" * filled + "░" * (bar_width - filled)
    return f"\r  [{bar}] {current:,}/{total:,}  ({pct:.1%})"


# ---------------------------------------------------------------------------
# Bulk mode
# ---------------------------------------------------------------------------

def download_all_plugins(
    client: TenableSCClient,
    fields: list[str],
    batch_size: int,
    max_plugins: int | None,
) -> list[dict[str, str]]:
    """Paginate through all plugins via GET /rest/plugin."""
    total = client.get_total_plugin_count()
    if max_plugins is not None:
        total = min(total, max_plugins)

    if total == 0:
        print("[WARN] API reported 0 plugins — nothing to download.")
        return []

    print(f"  Total plugins: {total:,}  |  batch size: {batch_size:,}")

    rows: list[dict[str, str]] = []
    offset = 0

    while offset < total:
        page_count = min(batch_size, total - offset)
        data = client.get_plugin_page(fields=fields, start=offset, count=page_count)

        response = data.get("response", {})
        plugins: list[dict] = (
            response.get("usable") or response.get("manageable") or []
        )

        if not plugins:
            break

        for plugin in plugins:
            rows.append(_flatten_plugin(plugin, fields))

        offset += page_count
        print(_progress_line(len(rows), total), end="", flush=True)

    print()
    return rows


# ---------------------------------------------------------------------------
# ID-list mode
# ---------------------------------------------------------------------------

def read_ids_from_csv(path: Path, id_column: str) -> list[str]:
    """
    Read non-empty plugin IDs from *id_column* in the CSV at *path*.

    Exits with a clear message when the file or column is missing.
    """
    if not path.exists():
        sys.exit(f"[ERROR] Input CSV not found: {path}")

    ids: list[str] = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or id_column not in reader.fieldnames:
            available = list(reader.fieldnames or [])
            sys.exit(
                f"[ERROR] Column '{id_column}' not found in '{path}'.\n"
                f"Available columns: {available}"
            )
        for row in reader:
            pid = str(row[id_column]).strip()
            if pid:
                ids.append(pid)

    return ids


def _fetch_one(
    client: TenableSCClient,
    plugin_id: str,
    fields: list[str] | None,
) -> dict[str, str] | None:
    """
    Fetch a single plugin and return a flat row dict.

    Returns None (instead of raising) so one bad ID does not abort the run.
    """
    try:
        data = client.get_plugin_by_id(plugin_id, fields)
        plugin = data.get("response", {})
        if not plugin:
            print(
                f"\n  [WARN] Empty response for plugin {plugin_id}",
                file=sys.stderr,
            )
            return None
        # Use the explicitly requested fields, or all keys from this response
        row_fields = fields if fields is not None else list(plugin.keys())
        return _flatten_plugin(plugin, row_fields)
    except TenableSCError as exc:
        print(f"\n  [WARN] Skipping plugin {plugin_id}: {exc}", file=sys.stderr)
        return None


def download_plugins_by_id(
    client: TenableSCClient,
    plugin_ids: list[str],
    fields: list[str] | None,
    workers: int,
) -> list[dict[str, str]]:
    """
    Fetch the given plugin IDs concurrently via GET /rest/plugin/{id}.

    Parameters
    ----------
    fields:
        Passed as ?fields=... to each request.  None means request all fields.
    workers:
        Number of concurrent HTTP threads.
    """
    total = len(plugin_ids)
    print(f"  Plugin IDs to fetch: {total:,}  |  workers: {workers}")

    rows: list[dict[str, str]] = []
    completed = 0
    failed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_fetch_one, client, pid, fields): pid
            for pid in plugin_ids
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            completed += 1
            if result is not None:
                rows.append(result)
            else:
                failed += 1
            print(_progress_line(completed, total), end="", flush=True)

    print()
    if failed:
        print(f"  [WARN] {failed} plugin(s) could not be fetched and were skipped.")
    return rows


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

def _discover_fieldnames(rows: list[dict[str, str]]) -> list[str]:
    """Return the ordered union of all keys across every row (first-seen order)."""
    seen: dict[str, None] = {}
    for row in rows:
        seen.update(dict.fromkeys(row.keys()))
    return list(seen.keys())


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=fieldnames,
            extrasaction="ignore",
            restval="",
        )
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="tenable_sc_fetch",
        description=(
            "Download Tenable Security Center plugin data to a CSV file.\n\n"
            "Modes:\n"
            "  Bulk mode     (default) — paginates GET /rest/plugin\n"
            "  ID-list mode  (--input-csv) — calls GET /rest/plugin/{id} per row"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    conn = ap.add_argument_group("connection")
    conn.add_argument(
        "--host",
        metavar="HOST",
        default=os.environ.get("TSC_HOST", ""),
        help="Tenable SC hostname or full URL. Overrides env var TSC_HOST.",
    )
    conn.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable SSL certificate verification (useful for self-signed certs)",
    )

    cred = ap.add_argument_group(
        "username / password authentication",
        "Flags take precedence over env vars TSC_USERNAME / TSC_PASSWORD.",
    )
    cred.add_argument(
        "-u", "--username",
        metavar="USER",
        default=os.environ.get("TSC_USERNAME", ""),
        help="Username for session-based auth. Overrides env var TSC_USERNAME.",
    )
    cred.add_argument(
        "-p", "--password",
        metavar="PASS",
        default=os.environ.get("TSC_PASSWORD", ""),
        help="Password for session-based auth. Overrides env var TSC_PASSWORD.",
    )

    keys = ap.add_argument_group(
        "API key authentication (Tenable SC 5.13+)",
        "Flags take precedence over env vars TSC_ACCESS_KEY / TSC_SECRET_KEY.",
    )
    keys.add_argument(
        "--access-key",
        metavar="ACCESS_KEY",
        default=os.environ.get("TSC_ACCESS_KEY", ""),
        help="API access key. Overrides env var TSC_ACCESS_KEY.",
    )
    keys.add_argument(
        "--secret-key",
        metavar="SECRET_KEY",
        default=os.environ.get("TSC_SECRET_KEY", ""),
        help="API secret key. Overrides env var TSC_SECRET_KEY.",
    )

    out = ap.add_argument_group("output")
    out.add_argument(
        "-o", "--output",
        metavar="FILE",
        default="",
        help="Output CSV path (default: plugins_YYYYMMDD_HHMMSS.csv)",
    )
    out.add_argument(
        "--fields",
        metavar="FIELDS",
        default="",
        help=(
            "Comma-separated list of API fields to request and write to CSV.\n"
            "Bulk mode default: 19 standard fields (see DEFAULT_FIELDS).\n"
            "ID-list mode default: all fields returned by the API."
        ),
    )

    bulk = ap.add_argument_group(
        "bulk mode options",
        "Used when --input-csv is not provided.",
    )
    bulk.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        metavar="N",
        help=f"Plugins per API page request (default: {DEFAULT_BATCH_SIZE})",
    )
    bulk.add_argument(
        "--max-plugins",
        type=int,
        default=None,
        metavar="N",
        help="Stop after N plugins (default: download all)",
    )

    id_grp = ap.add_argument_group(
        "ID-list mode options",
        "Activated when --input-csv is provided.",
    )
    id_grp.add_argument(
        "-i", "--input-csv",
        metavar="FILE",
        help="CSV file containing plugin IDs; each ID is fetched via GET /rest/plugin/{id}",
    )
    id_grp.add_argument(
        "--id-column",
        metavar="COL",
        default="id",
        help="Column name in --input-csv that holds the plugin IDs (default: id)",
    )
    id_grp.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        metavar="N",
        help=f"Concurrent HTTP workers for ID-list mode (default: {DEFAULT_WORKERS})",
    )

    return ap


def _validate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if not args.host:
        parser.error(
            "--host is required (or set the TSC_HOST environment variable)."
        )

    using_creds = bool(args.username or args.password)
    using_keys  = bool(args.access_key or args.secret_key)

    if not using_creds and not using_keys:
        parser.error(
            "Authentication required. Provide either:\n"
            "  --username / --password       (or env vars TSC_USERNAME / TSC_PASSWORD)\n"
            "  --access-key / --secret-key   (or env vars TSC_ACCESS_KEY / TSC_SECRET_KEY)"
        )
    if using_creds:
        if not args.username:
            parser.error(
                "--username is required with password authentication (or set TSC_USERNAME)."
            )
        if not args.password:
            parser.error(
                "--password is required with password authentication (or set TSC_PASSWORD)."
            )
    if using_keys:
        if not args.access_key:
            parser.error(
                "--access-key is required with API key authentication (or set TSC_ACCESS_KEY)."
            )
        if not args.secret_key:
            parser.error(
                "--secret-key is required with API key authentication (or set TSC_SECRET_KEY)."
            )
    if args.batch_size < 1:
        parser.error("--batch-size must be a positive integer.")
    if args.workers < 1:
        parser.error("--workers must be a positive integer.")


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()
    _validate(args, parser)

    # -- resolve field list --------------------------------------------------
    explicit_fields = [f.strip() for f in args.fields.split(",") if f.strip()]
    id_mode = bool(args.input_csv)

    # fields=None  means "request everything, discover header from responses"
    # fields=list  means "request exactly these, use them as CSV header"
    fields: list[str] | None
    if explicit_fields:
        fields = explicit_fields
    elif id_mode:
        fields = None
    else:
        fields = DEFAULT_FIELDS

    output_path = Path(
        args.output
        or f"plugins_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    )

    # -- authenticate --------------------------------------------------------
    client = TenableSCClient(args.host, verify_ssl=not args.no_verify)

    if args.username:
        print(f"[+] Authenticating as '{args.username}' on {args.host} ...")
        client.login(args.username, args.password)
        print("[+] Authenticated via session token.")
    else:
        client.set_api_keys(args.access_key, args.secret_key)
        print(f"[+] API key authentication configured for {args.host}.")

    # -- fetch ---------------------------------------------------------------
    t0 = time.monotonic()

    try:
        if id_mode:
            input_path = Path(args.input_csv)
            print(
                f"[+] Reading plugin IDs from '{input_path}' "
                f"(column: '{args.id_column}') ..."
            )
            plugin_ids = read_ids_from_csv(input_path, args.id_column)
            if not plugin_ids:
                print("[WARN] No plugin IDs found in the input file — nothing to fetch.")
                sys.exit(0)
            print(f"[+] Found {len(plugin_ids):,} plugin ID(s).")
            fields_label = ",".join(fields) if fields else "(all fields)"
            print(
                f"[+] Fetching from {client.base_url}/plugin/{{id}} "
                f"with fields={fields_label} ..."
            )
            rows = download_plugins_by_id(
                client=client,
                plugin_ids=plugin_ids,
                fields=fields,
                workers=args.workers,
            )
        else:
            print(f"[+] Fetching all plugins from {client.base_url}/plugin ...")
            rows = download_all_plugins(
                client=client,
                fields=fields,  # type: ignore[arg-type]  # always list in bulk mode
                batch_size=args.batch_size,
                max_plugins=args.max_plugins,
            )
    finally:
        client.logout()

    elapsed = time.monotonic() - t0

    if not rows:
        print("[WARN] No plugin data returned — no CSV written.")
        sys.exit(0)

    # -- resolve CSV header --------------------------------------------------
    if fields is not None:
        csv_fields = fields
    else:
        # Discover from actual responses (ID-list mode with no --fields)
        csv_fields = _discover_fieldnames(rows)
        print(f"  Discovered {len(csv_fields)} field(s) from API responses.")

    # -- write ---------------------------------------------------------------
    print(f"[+] Writing {len(rows):,} rows → '{output_path}' ...")
    write_csv(output_path, fieldnames=csv_fields, rows=rows)

    size_kb = output_path.stat().st_size / 1024
    print(
        f"[+] Done.  {len(rows):,} plugins saved to '{output_path}' "
        f"({size_kb:.1f} KB, {elapsed:.1f}s)."
    )


if __name__ == "__main__":
    main()

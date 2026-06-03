#!/usr/bin/env python3
"""
tenable_sc_fetch.py
===================
Downloads all plugin data from the Tenable Security Center REST API
and writes it to a CSV file.

Authentication options:
  1. Username / password  (session token via POST /rest/token)
  2. API key pair         (X-APIKey header — SC 5.13+)

Usage examples
--------------
  # Username / password:
  python tenable_sc_fetch.py --host sc.example.com -u admin -p secret

  # API key pair:
  python tenable_sc_fetch.py --host sc.example.com --access-key AK --secret-key SK

  # Custom output file and field list:
  python tenable_sc_fetch.py --host sc.example.com -u admin -p secret \\
      --output my_plugins.csv --fields id,name,severity,family,cvssV3BaseScore

  # Disable SSL verification (for self-signed certs):
  python tenable_sc_fetch.py --host sc.example.com -u admin -p secret --no-verify

  # Limit to first 500 plugins:
  python tenable_sc_fetch.py --host sc.example.com -u admin -p secret --max-plugins 500
"""

import argparse
import csv
import json
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
    "id",
    "name",
    "version",
    "type",
    "severity",
    "family",
    "modifiedTime",
    "publicationDate",
    "patchPublicationDate",
    "vulnPublicationDate",
    "exploitable",
    "cvssVector",
    "baseScore",
    "temporalScore",
    "cvssV3Vector",
    "cvssV3BaseScore",
    "checkType",
    "description",
    "copyright",
]

DEFAULT_BATCH_SIZE: int = 1000


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
        _raise_for_status(resp, "Login failed")
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

    # -- plugin fetch ---------------------------------------------------------

    def get_plugin_page(
        self,
        fields: list[str],
        start: int,
        count: int,
    ) -> dict:
        """Fetch one page of plugins starting at *start* with *count* entries."""
        params: dict[str, Any] = {
            "fields": ",".join(fields),
            "startOffset": start,
            "endOffset": start + count,
        }
        resp = self.session.get(f"{self.base_url}/plugin", params=params)
        _raise_for_status(resp, f"Failed to fetch plugins at offset {start}")
        return resp.json()

    def get_total_plugin_count(self) -> int:
        """Return the total number of plugins reported by the API."""
        data = self.get_plugin_page(fields=["id"], start=0, count=1)
        return int(data.get("response", {}).get("usableCount", 0))


# ---------------------------------------------------------------------------
# HTTP error helper
# ---------------------------------------------------------------------------

def _raise_for_status(resp: requests.Response, context: str) -> None:
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("error_msg", resp.text[:400])
        except Exception:
            detail = resp.text[:400]
        sys.exit(f"[ERROR] {context}: HTTP {resp.status_code} — {detail}")


# ---------------------------------------------------------------------------
# Value flattening
# ---------------------------------------------------------------------------

def _flatten_value(value: Any) -> str:
    """Convert any API value (dict, list, scalar) to a plain string."""
    if value is None:
        return ""
    if isinstance(value, dict):
        # Tenable SC commonly returns {"id": "2", "name": "Medium", ...}
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
# Download orchestration
# ---------------------------------------------------------------------------

def download_all_plugins(
    client: TenableSCClient,
    fields: list[str],
    batch_size: int,
    max_plugins: int | None,
) -> list[dict[str, str]]:
    """Page through all plugins and return a list of flat row dicts."""
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
        # The API may return plugins under "usable" or "manageable"
        plugins: list[dict] = response.get("usable") or response.get("manageable") or []

        if not plugins:
            # No more data even though total said otherwise — stop gracefully
            break

        for plugin in plugins:
            rows.append(_flatten_plugin(plugin, fields))

        offset += page_count
        print(_progress_line(len(rows), total), end="", flush=True)

    print()  # newline after progress bar
    return rows


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="tenable_sc_fetch",
        description=(
            "Download all plugin data from the Tenable Security Center REST API "
            "and write it to a CSV file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    conn = ap.add_argument_group("connection")
    conn.add_argument(
        "--host", required=True, metavar="HOST",
        help="Tenable SC hostname or full URL (e.g. sc.example.com or https://sc.example.com)",
    )
    conn.add_argument(
        "--no-verify", action="store_true",
        help="Disable SSL certificate verification (useful for self-signed certs)",
    )

    cred = ap.add_argument_group("username / password authentication")
    cred.add_argument("-u", "--username", metavar="USER")
    cred.add_argument("-p", "--password", metavar="PASS")

    keys = ap.add_argument_group("API key authentication (Tenable SC 5.13+)")
    keys.add_argument("--access-key", metavar="ACCESS_KEY")
    keys.add_argument("--secret-key", metavar="SECRET_KEY")

    out = ap.add_argument_group("output")
    out.add_argument(
        "-o", "--output", metavar="FILE", default="",
        help="Output CSV file path (default: plugins_YYYYMMDD_HHMMSS.csv)",
    )
    out.add_argument(
        "--fields", metavar="FIELDS",
        default=",".join(DEFAULT_FIELDS),
        help=(
            "Comma-separated list of API fields to include in the CSV.\n"
            f"Default: {','.join(DEFAULT_FIELDS)}"
        ),
    )

    fetch = ap.add_argument_group("fetch options")
    fetch.add_argument(
        "--batch-size", type=int, default=DEFAULT_BATCH_SIZE, metavar="N",
        help=f"Plugins to request per API call (default: {DEFAULT_BATCH_SIZE})",
    )
    fetch.add_argument(
        "--max-plugins", type=int, default=None, metavar="N",
        help="Stop after downloading N plugins (default: download all)",
    )

    return ap


def _validate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    using_creds = bool(args.username or args.password)
    using_keys  = bool(args.access_key or args.secret_key)

    if not using_creds and not using_keys:
        parser.error(
            "Authentication required. Provide either:\n"
            "  --username / --password\n"
            "  --access-key / --secret-key"
        )
    if using_creds:
        if not args.username:
            parser.error("--username is required with password authentication.")
        if not args.password:
            parser.error("--password is required with password authentication.")
    if using_keys:
        if not args.access_key:
            parser.error("--access-key is required with API key authentication.")
        if not args.secret_key:
            parser.error("--secret-key is required with API key authentication.")
    if args.batch_size < 1:
        parser.error("--batch-size must be a positive integer.")


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()
    _validate(args, parser)

    fields = [f.strip() for f in args.fields.split(",") if f.strip()]
    if not fields:
        parser.error("--fields produced an empty list.")

    output_path = Path(
        args.output
        or f"plugins_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    )

    # -- connect and authenticate --------------------------------------------
    client = TenableSCClient(args.host, verify_ssl=not args.no_verify)

    if args.username:
        print(f"[+] Authenticating as '{args.username}' on {args.host} ...")
        client.login(args.username, args.password)
        print("[+] Authenticated via session token.")
    else:
        client.set_api_keys(args.access_key, args.secret_key)
        print(f"[+] API key authentication configured for {args.host}.")

    # -- download -----------------------------------------------------------
    print(f"[+] Fetching plugins from {client.base_url}/plugin ...")
    t0 = time.monotonic()

    try:
        rows = download_all_plugins(
            client=client,
            fields=fields,
            batch_size=args.batch_size,
            max_plugins=args.max_plugins,
        )
    finally:
        client.logout()

    elapsed = time.monotonic() - t0

    if not rows:
        print("[WARN] No plugin data returned — no CSV written.")
        sys.exit(0)

    # -- write CSV ----------------------------------------------------------
    print(f"[+] Writing {len(rows):,} rows → '{output_path}' ...")
    write_csv(output_path, fieldnames=fields, rows=rows)

    size_kb = output_path.stat().st_size / 1024
    print(
        f"[+] Done.  {len(rows):,} plugins saved to '{output_path}' "
        f"({size_kb:.1f} KB, {elapsed:.1f}s)."
    )


if __name__ == "__main__":
    main()

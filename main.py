#!/usr/bin/env python3
"""
IP Reputation Checker
Checks IPs against AbuseIPDB, caches results in SQLite, and reports known-bad.

Usage:
  python ip_rep.py check 1.2.3.4
  python ip_rep.py check 1.2.3.4 8.8.8.8 10.0.0.1
  python ip_rep.py file ips.txt
  python ip_rep.py report
  python ip_rep.py report --min-score 50
"""

import json
import sqlite3
import argparse
import sys
import os
from datetime import datetime, timedelta

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass

# --- Config ---
DB_PATH         = "ip_reputation.db"
CACHE_TTL_HOURS = 24        # re-query after this many hours
ABUSE_SCORE_THRESHOLD = 25  # flag IPs at or above this score
ABUSEIPDB_URL   = "https://api.abuseipdb.com/api/v2/check"

# Set your AbuseIPDB API key here or via env var ABUSEIPDB_KEY
API_KEY = os.environ.get("ABUSEIPDB_KEY", "")


# --- Database ---

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_results (
            ip              TEXT PRIMARY KEY,
            abuse_score     INTEGER,
            country_code    TEXT,
            isp             TEXT,
            domain          TEXT,
            total_reports   INTEGER,
            last_reported   TEXT,
            is_whitelisted  INTEGER,
            queried_at      TEXT,
            raw_json        TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS query_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT,
            abuse_score INTEGER,
            flagged     INTEGER,
            queried_at  TEXT
        )
    """)
    conn.commit()


def cache_result(conn: sqlite3.Connection, ip: str, data: dict):
    now = datetime.utcnow().isoformat()
    conn.execute("""
        INSERT INTO ip_results
            (ip, abuse_score, country_code, isp, domain, total_reports,
             last_reported, is_whitelisted, queried_at, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            abuse_score    = excluded.abuse_score,
            country_code   = excluded.country_code,
            isp            = excluded.isp,
            domain         = excluded.domain,
            total_reports  = excluded.total_reports,
            last_reported  = excluded.last_reported,
            is_whitelisted = excluded.is_whitelisted,
            queried_at     = excluded.queried_at,
            raw_json       = excluded.raw_json
    """, (
        ip,
        data.get("abuseConfidenceScore", 0),
        data.get("countryCode", ""),
        data.get("isp", ""),
        data.get("domain", ""),
        data.get("totalReports", 0),
        data.get("lastReportedAt", ""),
        int(data.get("isWhitelisted") or False),
        now,
        json.dumps(data),
    ))
    conn.execute(
        "INSERT INTO query_log (ip, abuse_score, flagged, queried_at) VALUES (?, ?, ?, ?)",
        (ip, data.get("abuseConfidenceScore", 0),
         int(data.get("abuseConfidenceScore", 0) >= ABUSE_SCORE_THRESHOLD), now)
    )
    conn.commit()


def get_cached(conn: sqlite3.Connection, ip: str) -> sqlite3.Row | None:
    cutoff = (datetime.utcnow() - timedelta(hours=CACHE_TTL_HOURS)).isoformat()
    return conn.execute(
        "SELECT * FROM ip_results WHERE ip = ? AND queried_at > ?", (ip, cutoff)
    ).fetchone()


# --- API ---

def query_abuseipdb(ip: str) -> dict | None:
    if not API_KEY:
        print("[WARN] No API key set. Export ABUSEIPDB_KEY or set API_KEY in the script.")
        print("       Returning mock data for demonstration.\n")
        return _mock_response(ip)

    req = urllib.request.Request(
        f"{ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays=90&verbose",
        headers={
            "Key": API_KEY,
            "Accept": "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
            return body.get("data", {})
    except urllib.error.HTTPError as e:
        print(f"[ERROR] HTTP {e.code} for {ip}: {e.reason}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"[ERROR] Network error for {ip}: {e.reason}", file=sys.stderr)
    return None


def _mock_response(ip: str) -> dict:
    """Returns fake data when no API key is configured — useful for testing."""
    import hashlib
    seed = int(hashlib.md5(ip.encode()).hexdigest(), 16) % 100
    return {
        "ipAddress":            ip,
        "abuseConfidenceScore": seed,
        "countryCode":          ["US", "CN", "RU", "DE", "BR"][seed % 5],
        "isp":                  f"Mock ISP {seed % 10}",
        "domain":               f"example{seed % 10}.com",
        "totalReports":         seed // 3,
        "lastReportedAt":       "2024-10-01T12:00:00+00:00" if seed > 10 else None,
        "isWhitelisted":        seed < 5,
        "usageType":            "Data Center/Web Hosting/Transit",
    }


# --- Commands ---

def check_ips(ips: list[str], conn: sqlite3.Connection):
    results = []
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue

        cached = get_cached(conn, ip)
        if cached:
            source = "cache"
            data = json.loads(cached["raw_json"])
            score = cached["abuse_score"]
        else:
            source = "api"
            data = query_abuseipdb(ip)
            if data is None:
                print(f"  [!] Could not retrieve data for {ip}")
                continue
            cache_result(conn, ip, data)
            score = data.get("abuseConfidenceScore", 0)

        flagged = score >= ABUSE_SCORE_THRESHOLD
        results.append((ip, score, flagged, data, source))
        _print_result(ip, score, flagged, data, source)

    flagged_count = sum(1 for _, _, f, _, _ in results if f)
    print(f"\n[*] Checked {len(results)} IPs — {flagged_count} flagged (score >= {ABUSE_SCORE_THRESHOLD})")


def _print_result(ip, score, flagged, data, source):
    flag_str = "\033[91m[FLAGGED]\033[0m" if flagged else "\033[92m[CLEAN]  \033[0m"
    print(f"\n{flag_str} {ip}  (score: {score}/100)  [{source}]")
    print(f"  Country     : {data.get('countryCode', 'N/A')}")
    print(f"  ISP         : {data.get('isp', 'N/A')}")
    print(f"  Domain      : {data.get('domain', 'N/A')}")
    print(f"  Total reports: {data.get('totalReports', 0)}")
    last = data.get("lastReportedAt") or "Never"
    print(f"  Last reported: {last}")


def check_file(filepath: str, conn: sqlite3.Connection):
    try:
        with open(filepath, "r") as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Loaded {len(ips)} IPs from {filepath}\n")
    check_ips(ips, conn)


def show_report(conn: sqlite3.Connection, min_score: int = 0):
    rows = conn.execute("""
        SELECT ip, abuse_score, country_code, isp, total_reports, queried_at
        FROM ip_results
        WHERE abuse_score >= ?
        ORDER BY abuse_score DESC
    """, (min_score,)).fetchall()

    if not rows:
        print(f"[+] No results found with score >= {min_score}.")
        return

    print(f"\n{'IP':<18} {'Score':>6}  {'Country':>7}  {'Reports':>8}  {'Queried At':<20}  ISP")
    print("-" * 85)
    for r in rows:
        score_color = "\033[91m" if r["abuse_score"] >= ABUSE_SCORE_THRESHOLD else "\033[92m"
        reset = "\033[0m"
        print(
            f"{score_color}{r['ip']:<18}{reset} "
            f"{r['abuse_score']:>6}  "
            f"{(r['country_code'] or 'N/A'):>7}  "
            f"{r['total_reports']:>8}  "
            f"{r['queried_at'][:19]:<20}  "
            f"{r['isp'] or 'N/A'}"
        )

    print(f"\n[*] {len(rows)} record(s) shown (min score: {min_score})")

    # Pull flagged count from query_log
    flagged_total = conn.execute(
        "SELECT COUNT(*) FROM query_log WHERE flagged = 1"
    ).fetchone()[0]
    total_queries = conn.execute("SELECT COUNT(*) FROM query_log").fetchone()[0]
    print(f"[*] All-time: {flagged_total} flagged out of {total_queries} total queries")


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(
        description="Check IP reputation via AbuseIPDB with SQLite caching"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Check one or more IPs")
    p_check.add_argument("ips", nargs="+", help="IP address(es) to check")

    p_file = sub.add_parser("file", help="Check IPs from a text file (one per line)")
    p_file.add_argument("filepath", help="Path to file containing IPs")

    p_report = sub.add_parser("report", help="Show cached results from the database")
    p_report.add_argument(
        "--min-score", type=int, default=0,
        help="Only show IPs with abuse score >= this value (default: 0)"
    )

    args = parser.parse_args()

    conn = get_conn()
    init_db(conn)

    if args.command == "check":
        check_ips(args.ips, conn)
    elif args.command == "file":
        check_file(args.filepath, conn)
    elif args.command == "report":
        show_report(conn, min_score=args.min_score)

    conn.close()


if __name__ == "__main__":
    main()

import requests
import csv
import sys
import os
from datetime import datetime

# ── CONFIG ──────────────────────────────────────────────────────────────────
API_KEY = os.environ.get("VT_API_KEY", "YOUR_API_KEY_HERE")
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

# ── LOOKUP ───────────────────────────────────────────────────────────────────
def lookup_ip(ip):
    """Query VirusTotal for a single IP address."""
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(VT_URL.format(ip.strip()), headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "ip": ip.strip(),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "country": data.get("country", "N/A"),
                "as_owner": data.get("as_owner", "N/A"),
                "reputation": data.get("reputation", "N/A"),
                "status": "ok"
            }
        elif response.status_code == 404:
            return {"ip": ip.strip(), "status": "not_found"}
        elif response.status_code == 429:
            return {"ip": ip.strip(), "status": "rate_limited"}
        else:
            return {"ip": ip.strip(), "status": f"error_{response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"ip": ip.strip(), "status": f"connection_error: {e}"}

# ── OUTPUT ───────────────────────────────────────────────────────────────────
def save_results(results, output_file):
    """Write results to a CSV file."""
    fieldnames = ["ip", "malicious", "suspicious", "harmless", "undetected",
                  "country", "as_owner", "reputation", "status"]
    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            # Fill missing fields with N/A for error rows
            filled = {field: row.get(field, "N/A") for field in fieldnames}
            writer.writerow(filled)
    print(f"\n[+] Results saved to {output_file}")

# ── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print("Usage: python ip_checker.py <ip_list.txt>")
        print("Example: python ip_checker.py ips.txt")
        sys.exit(1)

    ip_file = sys.argv[1]

    if not os.path.exists(ip_file):
        print(f"[!] File not found: {ip_file}")
        sys.exit(1)

    if API_KEY == "YOUR_API_KEY_HERE":
        print("[!] Set your VirusTotal API key as the VT_API_KEY environment variable.")
        print("    export VT_API_KEY=your_key_here")
        sys.exit(1)

    with open(ip_file, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    if not ips:
        print("[!] No IPs found in file.")
        sys.exit(1)

    print(f"[*] Checking {len(ips)} IP(s) against VirusTotal...\n")

    results = []
    for i, ip in enumerate(ips, 1):
        print(f"[{i}/{len(ips)}] Checking {ip}...", end=" ")
        result = lookup_ip(ip)
        results.append(result)

        if result["status"] == "ok":
            flag = " ⚠️  MALICIOUS" if result["malicious"] > 0 else ""
            print(f"malicious={result['malicious']} suspicious={result['suspicious']} country={result['country']}{flag}")
        else:
            print(f"status={result['status']}")

    # Save to timestamped CSV
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"ip_report_{timestamp}.csv"
    save_results(results, output_file)

    # Summary
    malicious_count = sum(1 for r in results if r.get("malicious", 0) > 0)
    print(f"\n[*] Summary: {len(ips)} IPs checked | {malicious_count} flagged as malicious")

if __name__ == "__main__":
    main()

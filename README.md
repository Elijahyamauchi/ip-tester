# IP Reputation Checker

A Python command-line tool that checks a list of IP addresses against the VirusTotal threat intelligence API and saves results to a CSV report.

Built as part of a security tooling portfolio focused on threat detection and SOC analyst workflows.

---

## What It Does

- Reads a list of IP addresses from a text file (one IP per line)
- Queries the VirusTotal API for each IP
- Displays live results in the terminal as it runs
- Saves a timestamped CSV report with full results

---

## Example Output

```
[*] Checking 3 IP(s) against VirusTotal...

[1/3] Checking 185.220.101.1... malicious=12 suspicious=2 country=DE ⚠️  MALICIOUS
[2/3] Checking 8.8.8.8...       malicious=0  suspicious=0 country=US
[3/3] Checking 103.21.244.0...  malicious=0  suspicious=1 country=AU

[+] Results saved to ip_report_20260328_142301.csv

[*] Summary: 3 IPs checked | 1 flagged as malicious
```

### CSV Output Fields

| Field | Description |
|---|---|
| ip | IP address checked |
| malicious | Number of engines flagging as malicious |
| suspicious | Number of engines flagging as suspicious |
| harmless | Number of engines flagging as harmless |
| undetected | Number of engines with no verdict |
| country | Country of origin |
| as_owner | Autonomous system owner |
| reputation | VirusTotal community reputation score |
| status | ok / not_found / rate_limited / error |

---

## Setup

**Requirements**
- Python 3.x
- `requests` library

```bash
pip install requests
```

**VirusTotal API Key**

Sign up for a free account at [virustotal.com](https://www.virustotal.com) to get an API key.

Set it as an environment variable:

```bash
# Linux / macOS
export VT_API_KEY=your_api_key_here

# Windows (PowerShell)
$env:VT_API_KEY="your_api_key_here"
```

---

## Usage

Create a text file with one IP per line:

```
185.220.101.1
8.8.8.8
103.21.244.0
```

Run the script:

```bash
python ip_checker.py ips.txt
```

Results are saved automatically to a timestamped CSV in the same directory.

---

## Notes

- Free VirusTotal API accounts are limited to 4 requests per minute. For larger lists, consider adding a delay between requests.
- API key is loaded from the `VT_API_KEY` environment variable — never hardcode keys in source files.

---

## Tech Stack

- Python 3
- [VirusTotal API v3](https://developers.virustotal.com/reference/overview)
- `requests`, `csv`, `os`, `sys`

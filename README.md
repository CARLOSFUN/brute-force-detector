# Brute Force Detector

A Python-based SOC tool that detects brute force login attempts using **Azure Log Analytics** sign-in data, enriches flagged IPs with **AbuseIPDB** threat intelligence, and displays results in a live web dashboard.

Built against a live Azure environment with real internet-facing attack traffic.

---

## How It Works

1. Pulls failed Azure AD sign-in logs from Log Analytics using KQL (`SigninLogs`)
2. Applies a sliding time-window algorithm to detect IPs exceeding a failure threshold
3. Classifies each attack using the **MITRE ATT&CK** framework (T1110.001 / T1110.003 / T1110.004)
4. Enriches flagged IPs with AbuseIPDB reputation data (abuse score, country, ISP)
5. Displays results in a SOC-style web dashboard with day-range toggle
6. Saves a timestamped CSV report on every scan

---

## Web Dashboard

```bash
python app.py
```

Open your browser to **http://localhost:5000**

**Dashboard features:**
- Day toggle — scan 1, 3, 7, 14, or 30 days of log data
- Summary cards — Total Failed Logins, Flagged IPs, Known Malicious, Top Attacker IP
- Attack Timeline chart — failed login volume per hour
- Top Attacking IPs chart — ranked bar of highest-volume attackers
- Results table — IP, failure count, accounts targeted, country, ISP, abuse score, MITRE tag, status
- Color-coded abuse score badges (red / yellow / green)
- CSV report saved locally on every scan

---

## CLI Mode

```bash
python main.py
```

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Log into Azure CLI
```bash
az login
```
No service principal needed — authentication uses your existing Azure CLI session.

### 3. Configure `config.py`
```python
AZURE_WORKSPACE_ID  = "your-log-analytics-workspace-id"
ABUSEIPDB_API_KEY   = "your-abuseipdb-api-key"
```

Get your free AbuseIPDB API key at [abuseipdb.com](https://www.abuseipdb.com).

### 4. Run
```bash
python app.py        # Web dashboard at http://localhost:5000
python main.py       # CLI report
```

---

## Configuration (`config.py`)

| Setting | Default | Description |
|---|---|---|
| `AZURE_WORKSPACE_ID` | — | Your Log Analytics Workspace ID |
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB API key for IP reputation lookups |
| `FAILED_LOGIN_THRESHOLD` | 5 | Failed logins within the window to flag an IP |
| `TIME_WINDOW_MINUTES` | 10 | Rolling detection window (minutes) |
| `ABUSEIPDB_CONFIDENCE_MIN` | 25 | Minimum abuse score (%) to mark as malicious |
| `LOOKBACK_HOURS` | 24 | Default hours of log history to query |

---

## MITRE ATT&CK Classification

Each flagged IP is automatically classified based on attack pattern:

| Technique | ID | Trigger |
|---|---|---|
| Password Guessing | T1110.001 | One account targeted repeatedly |
| Password Spraying | T1110.003 | Many accounts, few attempts each |
| Credential Stuffing | T1110.004 | Many accounts, high attempt volume |

---

## Project Structure

```
main.py              # CLI entry point
app.py               # Flask web server (dashboard)
azure_logs.py        # Azure Log Analytics connection and KQL query
detector.py          # Sliding-window brute force detection + MITRE tagging
ip_enrichment.py     # AbuseIPDB threat intelligence IP lookup
report.py            # Console and CSV report generation
config.py            # Credentials and thresholds (gitignored)
templates/
  index.html         # SOC-style web dashboard UI
reports/             # Timestamped CSV reports (gitignored)
requirements.txt     # Python dependencies
```

---

## Data Sources

| Source | Table | Data |
|---|---|---|
| Azure Log Analytics | `SigninLogs` | Failed Azure AD authentication attempts |
| AbuseIPDB API | — | IP reputation, abuse history, ISP, country |

> **Note:** VM-level brute force (EventID 4625) can be added by enabling Windows audit logon failure policy and connecting VMs to the Log Analytics workspace.

---

## Requirements

- Python 3.8+
- Azure account with Log Analytics workspace
- Log Analytics Reader role on the workspace
- Free AbuseIPDB account

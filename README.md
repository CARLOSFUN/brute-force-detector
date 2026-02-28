# Brute Force Detector

A Python-based SOC tool that detects brute force login attempts using **Azure Log Analytics** sign-in data, enriches flagged IPs with **AbuseIPDB** threat intelligence, and displays results in a live web dashboard.

Built inside a real-world Cyber Range environment (LOG(N) Pacific) with 1,600+ users and live internet-facing attack traffic.

---

## How It Works

1. Pulls failed Azure AD sign-in logs from Log Analytics using KQL (`SigninLogs`)
2. Applies a sliding time-window algorithm to detect IPs exceeding a failure threshold
3. Enriches flagged IPs with AbuseIPDB reputation data (abuse score, country, ISP)
4. Displays results in a SOC-style web dashboard with day-range toggle
5. Saves a timestamped CSV report on every scan

---

## Web Dashboard

Run the Flask web server to access the dashboard:

```bash
python app.py
```

Open your browser to **http://localhost:5000**

**Dashboard features:**
- Day toggle — scan 1, 3, 7, 14, or 30 days of log data
- Summary cards — Total Failed Logins, Flagged IPs, Known Malicious, Top Attacker
- Results table — IP, failure count, targeted account, target device, country, ISP, abuse score, status badge
- Color-coded abuse score badges (red / yellow / green)
- CSV report saved on every scan

---

## CLI Mode

Run without the web server for a quick terminal report:

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
Sign in with your Cyber Range Azure account. No service principal needed — authentication uses your existing session.

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

## Project Structure

```
main.py              # CLI entry point
app.py               # Flask web server (dashboard)
azure_logs.py        # Azure Log Analytics connection and KQL query
detector.py          # Sliding-window brute force detection algorithm
ip_enrichment.py     # AbuseIPDB threat intelligence IP lookup
report.py            # Console and CSV report generation
config.py            # Credentials and thresholds (gitignored)
templates/
  index.html         # SOC-style web dashboard UI
requirements.txt     # Python dependencies
```

---

## Data Source

| Source | Table | Data |
|---|---|---|
| Azure Log Analytics | `SigninLogs` | Failed Azure AD authentication attempts |
| AbuseIPDB API | — | IP reputation, abuse history, ISP, country |

> **Note:** VM-level brute force (EventID 4625) requires Windows audit policy and Log Analytics agent configured on each VM. The Cyber Range admin can enable this to add RDP/SMB brute force detection.

---

## Environment

- **Platform:** Azure (LOG(N) Pacific Cyber Range)
- **Users:** 1,600+
- **Exposure:** Internet-facing — real external attackers generate live data
- **Auth:** Azure CLI (`az login`) — no secrets stored in code

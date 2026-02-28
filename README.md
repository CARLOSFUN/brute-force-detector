# Brute Force Detector

A Python-based SOC tool that detects brute force login attempts using **Azure Log Analytics** sign-in data and enriches flagged IPs with **AbuseIPDB** threat intelligence.

Built as part of a real-world Cyber Range environment with 1,600+ users and live attack traffic.

---

## How It Works

1. Pulls failed Azure AD sign-in logs from Log Analytics (via KQL)
2. Applies a sliding time-window algorithm to detect IPs exceeding a failure threshold
3. Enriches flagged IPs with AbuseIPDB reputation data (confidence score, country, ISP)
4. Outputs a formatted console report and saves a timestamped CSV

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure credentials
Edit `config.py` and fill in:
- Azure Tenant ID, Client ID, Client Secret
- Azure Log Analytics Workspace ID
- AbuseIPDB API key (free at [abuseipdb.com](https://www.abuseipdb.com))

### 3. Run
```bash
python main.py
```

---

## Configuration (`config.py`)

| Setting | Default | Description |
|---|---|---|
| `FAILED_LOGIN_THRESHOLD` | 5 | Failed logins needed to flag an IP |
| `TIME_WINDOW_MINUTES` | 10 | Rolling window duration |
| `ABUSEIPDB_CONFIDENCE_MIN` | 25 | Minimum abuse score to mark as malicious |
| `LOOKBACK_HOURS` | 24 | How far back to query Azure logs |

---

## Project Structure

```
main.py           # Entry point
azure_logs.py     # Azure Log Analytics connection and KQL query
detector.py       # Brute force pattern detection logic
ip_enrichment.py  # AbuseIPDB threat intelligence lookup
report.py         # Console and CSV report generation
config.py         # All credentials and thresholds (edit this)
```

---

## Azure Setup Required

You need a **Service Principal** in Azure with read access to your Log Analytics Workspace:

```bash
az ad sp create-for-rbac --name "BruteForceDetector" --role "Log Analytics Reader" \
  --scopes /subscriptions/{subscription-id}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}
```

This outputs your `clientId`, `clientSecret`, and `tenantId` for `config.py`.

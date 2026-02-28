# config.example.py
# Copy this file to config.py and fill in your values before running.

# Azure Log Analytics settings
# No client ID or secret needed — authentication uses your Azure CLI login (az login)
AZURE_WORKSPACE_ID = "your-log-analytics-workspace-id"

# AbuseIPDB settings
# Get a free API key at https://www.abuseipdb.com
ABUSEIPDB_API_KEY = "your-abuseipdb-api-key"

# Detection thresholds
FAILED_LOGIN_THRESHOLD = 5       # Number of failed logins within the window to flag an IP
TIME_WINDOW_MINUTES = 10         # Rolling detection window (minutes)
ABUSEIPDB_CONFIDENCE_MIN = 25    # Minimum abuse score (%) to mark as malicious

# Lookback window for log queries (hours)
LOOKBACK_HOURS = 24

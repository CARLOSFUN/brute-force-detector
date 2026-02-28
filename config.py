# config.py
# Edit these values before running the detector

# Azure Log Analytics settings
# No client ID or secret needed — authentication uses your Azure CLI login (az login)
AZURE_WORKSPACE_ID = "YOUR_LOG_ANALYTICS_WORKSPACE_ID"

# AbuseIPDB settings
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"

# Detection thresholds
FAILED_LOGIN_THRESHOLD = 5       # Number of failed logins to trigger alert
TIME_WINDOW_MINUTES = 10         # Time window to count failures within
ABUSEIPDB_CONFIDENCE_MIN = 25    # Minimum abuse confidence % to flag an IP (0-100)

# Lookback window for log queries (hours)
LOOKBACK_HOURS = 24

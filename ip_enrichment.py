# ip_enrichment.py
# Enriches flagged IPs with threat intelligence from AbuseIPDB

import requests
import config
from concurrent.futures import ThreadPoolExecutor, as_completed


def check_ip(ip: str) -> dict:
    """
    Queries AbuseIPDB for reputation data on a single IP.
    Returns a dict with abuse confidence score, country, ISP, and usage type.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": config.ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "IPAddress": ip,
            "AbuseConfidenceScore": data.get("abuseConfidenceScore", 0),
            "Country": data.get("countryCode", "Unknown"),
            "ISP": data.get("isp", "Unknown"),
            "UsageType": data.get("usageType", "Unknown"),
            "TotalReports": data.get("totalReports", 0),
            "LastReportedAt": data.get("lastReportedAt", "Never"),
            "IsMalicious": data.get("abuseConfidenceScore", 0) >= config.ABUSEIPDB_CONFIDENCE_MIN
        }
    except requests.RequestException as e:
        print(f"[ip_enrichment] Failed to check {ip}: {e}")
        return {
            "IPAddress": ip,
            "AbuseConfidenceScore": -1,
            "Country": "Error",
            "ISP": "Error",
            "UsageType": "Error",
            "TotalReports": -1,
            "LastReportedAt": "Error",
            "IsMalicious": False
        }


def enrich_flagged_ips(flagged_df):
    """
    Takes the flagged IPs DataFrame from detector.py and adds AbuseIPDB data.
    Returns the enriched DataFrame.
    """
    import pandas as pd

    if flagged_df.empty:
        return flagged_df

    print(f"[ip_enrichment] Checking {len(flagged_df)} IP(s) against AbuseIPDB (parallel)...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        enrichment_results = list(executor.map(check_ip, flagged_df["IPAddress"]))
    enrichment_df = pd.DataFrame(enrichment_results)

    merged = flagged_df.merge(enrichment_df, on="IPAddress", how="left")
    return merged

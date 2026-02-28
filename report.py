# report.py
# Generates a formatted alert report from enriched brute force data

import pandas as pd
from datetime import datetime


def print_console_report(df: pd.DataFrame):
    """Prints a formatted summary to the terminal."""
    if df.empty:
        print("\n[report] No threats to report.")
        return

    print("\n" + "=" * 70)
    print("  BRUTE FORCE DETECTION REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    for _, row in df.iterrows():
        malicious_tag = "*** KNOWN MALICIOUS ***" if row.get("IsMalicious") else ""
        print(f"\nIP Address       : {row['IPAddress']}  {malicious_tag}")
        print(f"Failure Count    : {row['FailureCount']} attempts in {row['WindowMinutes']} minutes")
        print(f"Window Start     : {row['WindowStart']}")
        print(f"Accounts Targeted: {row['TargetedAccounts']}")
        print(f"Unique Accounts  : {row['UniqueAccountsTargeted']}")
        print(f"Location (Azure) : {row['Location']}")
        print(f"Country (IPDB)   : {row.get('Country', 'N/A')}")
        print(f"ISP              : {row.get('ISP', 'N/A')}")
        print(f"Usage Type       : {row.get('UsageType', 'N/A')}")
        print(f"Abuse Score      : {row.get('AbuseConfidenceScore', 'N/A')}%")
        print(f"Total Reports    : {row.get('TotalReports', 'N/A')}")
        print(f"Last Reported    : {row.get('LastReportedAt', 'N/A')}")
        print("-" * 70)

    print(f"\nTotal Flagged IPs: {len(df)}")
    known_bad = df[df.get("IsMalicious", False) == True] if "IsMalicious" in df.columns else pd.DataFrame()
    print(f"Known Malicious  : {len(known_bad)}")
    print("=" * 70 + "\n")


def save_csv_report(df: pd.DataFrame):
    """Saves the full report to a timestamped CSV file."""
    if df.empty:
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"brute_force_report_{timestamp}.csv"
    df.to_csv(filename, index=False)
    print(f"[report] Report saved to {filename}")

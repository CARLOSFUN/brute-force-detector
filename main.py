# main.py
# Entry point for the Brute Force Detector
# Run: python main.py

from azure_logs import fetch_failed_logins
from detector import detect_brute_force
from ip_enrichment import enrich_flagged_ips
from report import print_console_report, save_csv_report


def main():
    print("\n[*] Starting Brute Force Detector...")

    # Step 1: Pull failed login events from Azure Log Analytics
    print("\n[1/4] Fetching failed login events from Azure...")
    failed_logins = fetch_failed_logins()

    # Step 2: Detect brute force patterns
    print("\n[2/4] Analyzing for brute force patterns...")
    flagged_ips = detect_brute_force(failed_logins)

    # Step 3: Enrich flagged IPs with AbuseIPDB threat intel
    print("\n[3/4] Enriching flagged IPs with threat intelligence...")
    enriched = enrich_flagged_ips(flagged_ips)

    # Step 4: Generate report
    print("\n[4/4] Generating report...")
    print_console_report(enriched)
    save_csv_report(enriched)

    print("[*] Done.\n")


if __name__ == "__main__":
    main()

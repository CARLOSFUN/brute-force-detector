# detector.py
# Analyzes failed login data and flags brute force attempts

import pandas as pd
import config


def detect_brute_force(df: pd.DataFrame) -> pd.DataFrame:
    """
    Groups failed logins by IP address within rolling time windows.
    Flags any IP that exceeds the threshold within the configured time window.

    Returns a DataFrame of offending IPs with failure counts and targeted accounts.
    """
    if df.empty:
        print("[detector] No login data to analyze.")
        return pd.DataFrame()

    df["TimeGenerated"] = pd.to_datetime(df["TimeGenerated"])
    df = df.sort_values("TimeGenerated")

    window = pd.Timedelta(minutes=config.TIME_WINDOW_MINUTES)
    flagged = []

    for ip, group in df.groupby("IPAddress"):
        group = group.sort_values("TimeGenerated")
        times = group["TimeGenerated"].tolist()

        # Sliding window: count failures within each window
        max_count = 0
        window_start = None
        for i, t in enumerate(times):
            count = sum(1 for t2 in times if t <= t2 <= t + window)
            if count > max_count:
                max_count = count
                window_start = t

        if max_count >= config.FAILED_LOGIN_THRESHOLD:
            targeted_accounts = group["Account"].unique().tolist()
            targeted_vms = [v for v in group["Computer"].unique().tolist() if v]
            flagged.append({
                "IPAddress": ip,
                "FailureCount": max_count,
                "WindowStart": window_start,
                "WindowMinutes": config.TIME_WINDOW_MINUTES,
                "TargetedAccounts": ", ".join(targeted_accounts),
                "UniqueAccountsTargeted": len(targeted_accounts),
                "TargetedVMs": ", ".join(targeted_vms) if targeted_vms else "Unknown",
            })

    if flagged:
        result = pd.DataFrame(flagged).sort_values("FailureCount", ascending=False)
        print(f"[detector] {len(result)} IP(s) flagged for brute force activity")
        return result
    else:
        print("[detector] No brute force activity detected.")
        return pd.DataFrame()

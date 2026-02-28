# azure_logs.py
# Connects to Azure Log Analytics and pulls failed sign-in events

from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.identity import AzureCliCredential
from datetime import timedelta
import pandas as pd
import os
import config

# Ensure Azure CLI is on the PATH regardless of which terminal is used
_AZ_PATH = r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin"
if _AZ_PATH not in os.environ.get("PATH", ""):
    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + _AZ_PATH


def get_credential():
    """Authenticate to Azure using your existing Azure CLI login (az login)."""
    return AzureCliCredential()


def fetch_failed_logins(lookback_hours=None):
    """
    Query Azure Log Analytics for failed Azure AD sign-in events (SigninLogs).
    Returns a DataFrame with columns: TimeGenerated, IPAddress, Account, Computer, LogonType

    Note: VM-level EventID 4625 logging is not enabled in this Cyber Range workspace.
    SigninLogs captures real external brute force attempts against Azure AD accounts.
    """
    if lookback_hours is None:
        lookback_hours = config.LOOKBACK_HOURS

    credential = get_credential()
    client = LogsQueryClient(credential)

    # KQL query — pulls failed Azure AD sign-ins from external attackers
    # ResultType != 0 means failed authentication
    # Includes VM name via DeviceDetail where available
    query = """
    SigninLogs
    | where TimeGenerated >= ago({hours}h)
    | where ResultType != "0"
    | project TimeGenerated,
              IPAddress,
              Account = UserPrincipalName,
              Computer = tostring(DeviceDetail.displayName),
              LogonType = "AzureAD"
    | order by TimeGenerated desc
    """.format(hours=lookback_hours)

    response = client.query_workspace(
        workspace_id=config.AZURE_WORKSPACE_ID,
        query=query,
        timespan=timedelta(hours=lookback_hours)
    )

    if response.status == LogsQueryStatus.SUCCESS:
        data = response.tables[0]
        df = pd.DataFrame(data.rows, columns=data.columns)
        print(f"[azure_logs] Fetched {len(df)} failed login events from the last {lookback_hours}h")
        return df
    else:
        print(f"[azure_logs] Query failed: {response.partial_error}")
        return pd.DataFrame()

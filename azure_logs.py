# azure_logs.py
# Connects to Azure Log Analytics and pulls failed sign-in events

from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.identity import ClientSecretCredential
from datetime import timedelta
import pandas as pd
import config


def get_credential():
    """Authenticate to Azure using service principal credentials."""
    return ClientSecretCredential(
        tenant_id=config.AZURE_TENANT_ID,
        client_id=config.AZURE_CLIENT_ID,
        client_secret=config.AZURE_CLIENT_SECRET
    )


def fetch_failed_logins():
    """
    Query Azure Log Analytics for failed sign-in events.
    Returns a DataFrame with columns: TimeGenerated, IPAddress, UserPrincipalName, ResultDescription
    """
    credential = get_credential()
    client = LogsQueryClient(credential)

    # KQL query — pulls failed Azure AD sign-ins
    query = """
    SigninLogs
    | where TimeGenerated >= ago({hours}h)
    | where ResultType != "0"
    | project TimeGenerated, IPAddress, UserPrincipalName, ResultType, ResultDescription, Location
    | order by TimeGenerated desc
    """.format(hours=config.LOOKBACK_HOURS)

    response = client.query_workspace(
        workspace_id=config.AZURE_WORKSPACE_ID,
        query=query,
        timespan=timedelta(hours=config.LOOKBACK_HOURS)
    )

    if response.status == LogsQueryStatus.SUCCESS:
        data = response.tables[0]
        df = pd.DataFrame(data.rows, columns=[col.name for col in data.columns])
        print(f"[azure_logs] Fetched {len(df)} failed login events from the last {config.LOOKBACK_HOURS}h")
        return df
    else:
        print(f"[azure_logs] Query failed: {response.partial_error}")
        return pd.DataFrame()

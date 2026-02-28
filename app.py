# app.py
# Flask web server for the Brute Force Detector dashboard
# Run: python app.py  then open http://localhost:5000

from flask import Flask, render_template, request, jsonify
from datetime import datetime
import pandas as pd

from azure_logs import fetch_failed_logins
from detector import detect_brute_force
from ip_enrichment import enrich_flagged_ips

app = Flask(__name__)


def df_to_records(df: pd.DataFrame) -> list:
    """Convert a DataFrame to a JSON-safe list of dicts (timestamps become strings)."""
    if df.empty:
        return []
    df = df.copy()
    for col in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[col]):
            df[col] = df[col].astype(str)
    # Replace NaN/None with readable defaults
    df = df.fillna("N/A")
    return df.to_dict(orient="records")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    days = int(data.get("days", 1))
    lookback_hours = days * 24

    try:
        failed_logins = fetch_failed_logins(lookback_hours=lookback_hours)
        flagged = detect_brute_force(failed_logins)
        enriched = enrich_flagged_ips(flagged)

        total_events = len(failed_logins)
        flagged_count = len(enriched)
        malicious_count = int(enriched["IsMalicious"].sum()) if not enriched.empty and "IsMalicious" in enriched.columns else 0
        top_ip = enriched.iloc[0]["IPAddress"] if not enriched.empty else "None"

        # Build hourly attack chart data from raw failed logins
        chart_labels, chart_values = [], []
        if not failed_logins.empty:
            failed_logins["TimeGenerated"] = pd.to_datetime(failed_logins["TimeGenerated"], utc=True)
            hourly = (
                failed_logins
                .groupby(failed_logins["TimeGenerated"].dt.floor("h"))
                .size()
                .reset_index(name="count")
            )
            chart_labels = hourly["TimeGenerated"].dt.strftime("%m/%d %H:%M").tolist()
            chart_values = hourly["count"].tolist()

        # Top attacking IPs by failure count (for bar chart)
        top_attacker_labels = enriched["IPAddress"].head(5).tolist() if not enriched.empty else []
        top_attacker_values = enriched["FailureCount"].head(5).tolist() if not enriched.empty else []

        return jsonify({
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "days": days,
            "total_events": total_events,
            "flagged_count": flagged_count,
            "malicious_count": malicious_count,
            "top_ip": top_ip,
            "flagged_ips": df_to_records(enriched),
            "chart_labels": chart_labels,
            "chart_values": chart_values,
            "top_attacker_labels": top_attacker_labels,
            "top_attacker_values": top_attacker_values,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)

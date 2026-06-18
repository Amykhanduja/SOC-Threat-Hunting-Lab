import json
import sys

ALERT_FILE = "alerts/alerts.json"

if len(sys.argv) != 3:
    print("Usage:")
    print("python3 review_alert.py ALERT_ID TP")
    print("python3 review_alert.py ALERT_ID FP")
    exit()

alert_id = sys.argv[1]
verdict = sys.argv[2].upper()

if verdict not in ["TP", "FP"]:
    print("Verdict must be TP or FP")
    exit()

with open(ALERT_FILE, "r") as f:
    alerts = json.load(f)

found = False

for alert in alerts:

    if alert["alert_id"] == alert_id:

        alert["review_status"] = verdict
        found = True
        break

if found:

    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=4)

    print(f"Alert {alert_id} marked as {verdict}")

else:

    print("Alert not found")

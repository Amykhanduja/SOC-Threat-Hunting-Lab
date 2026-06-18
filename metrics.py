import json

ALERT_FILE = "alerts/alerts.json"

try:
    with open(ALERT_FILE, "r") as f:
        alerts = json.load(f)

except:
    alerts = []

tp = 0
fp = 0
pending = 0

for alert in alerts:

    status = alert.get("review_status", "Pending")

    if status == "TP":
        tp += 1

    elif status == "FP":
        fp += 1

    else:
        pending += 1

reviewed = tp + fp

if reviewed > 0:
    fpr = (fp / reviewed) * 100
else:
    fpr = 0

print("\n=== Detection Metrics ===")
print(f"Total Alerts : {len(alerts)}")
print(f"TP           : {tp}")
print(f"FP           : {fp}")
print(f"Pending      : {pending}")
print(f"FPR          : {fpr:.2f}%")
print("=========================\n")

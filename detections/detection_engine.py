from collections import Counter
import re

LOG_FILE = "/var/log/auth.log"

failed_ips = Counter()
sudo_events = 0
user_creation = 0

with open(LOG_FILE, "r") as f:
    logs = f.readlines()

for line in logs:

    if "Failed password" in line:

        match = re.search(
            r'from (\d+\.\d+\.\d+\.\d+)',
            line
        )

        if match:
            ip = match.group(1)
            failed_ips[ip] += 1

    if "sudo:" in line:
        sudo_events += 1

    if "useradd" in line:
        user_creation += 1

print("\n===== SOC DETECTION RESULTS =====\n")

for ip, count in failed_ips.items():

    if count >= 3:
        print(f"[HIGH] Brute Force Detected")
        print(f"Source IP: {ip}")
        print(f"Attempts: {count}")
        print("MITRE: T1110\n")

if sudo_events:
    print("[MEDIUM] Privilege Escalation Activity")
    print(f"Events: {sudo_events}")
    print("MITRE: T1078\n")

if user_creation:
    print("[MEDIUM] New User Creation")
    print(f"Events: {user_creation}")
    print("MITRE: T1136\n")

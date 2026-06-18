print("######## NEW VERSION LOADED ########")
import os
import time
import re
import uuid
import json
from collections import Counter
from datetime import datetime, timezone, timedelta
LOG_FILE = "/var/log/auth.log"
IOC_FILE = "iocs/iocs.json"
BRUTEFORCE_LOG = "logs/bruteforce_logs.txt"
SUDO_LOG       = "logs/sudo_logs.txt"
USER_LOG       = "logs/user_creation_logs.txt"

failed_ips = Counter()
alerted_ips = {}

def generate_alert_id():
    return "ALT-" + str(uuid.uuid4())[:8]

def calculate_bruteforce_confidence(failures):

    confidence = 0

    if failures >= 3:
        confidence += 40

    if failures >= 5:
        confidence += 30

    if failures >= 10:
        confidence += 30

    return min(confidence, 100)


def get_severity(confidence):

    if confidence >= 80:
        return "Critical"

    elif confidence >= 60:
        return "High"

    elif confidence >= 40:
        return "Medium"

    else:
        return "Low"

def save_alert(alert):

    file_path = "alerts/alerts.json"

    try:
        with open(file_path, "r") as f:
            alerts = json.load(f)

    except:
        alerts = []

    alerts.append(alert)

    with open(file_path, "w") as f:
        json.dump(alerts, f, indent=4)


def save_ioc(ip, attack, severity, mitre):
    try:
        with open(IOC_FILE, "r") as f:
            data = json.load(f)
    except:
        data = []

    ioc = {
        "timestamp": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST"),
        "ip": ip,
        "attack": attack,
        "severity": severity,
        "mitre": mitre
    }

    data.append(ioc)

    with open(IOC_FILE, "w") as f:
        json.dump(data, f, indent=4)

    print("[IOC SAVED]")

IST = timezone(timedelta(hours=5, minutes=30))

def save_to_log(logfile, message):
    now_ist = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")
    with open(logfile, "a") as f:
        f.write(f"{now_ist} {message}\n")


print("=== SOC Realtime Monitor Started ===\n")

with open(LOG_FILE, "r") as f:

    # Move to end of file
    f.seek(0, 2)

    while True:

        line = f.readline()

        if not line:
            time.sleep(0.2)
            continue

        if "Failed password" in line:

            match = re.search(
                r'from (\d+\.\d+\.\d+\.\d+)',
                line
            )

            if match:

                ip = match.group(1)

                failed_ips[ip] += 1

                attempts = failed_ips[ip]

                print(
                    f"[INFO] Failed Login "
                    f"IP={ip} "
                    f"Attempts={attempts}"
                )

                if attempts >= 3:
                     confidence = calculate_bruteforce_confidence(
                         attempts
                     )

                     severity = get_severity(
                         confidence
                     )
                     previous_severity = alerted_ips.get(ip)

                     if previous_severity == severity:
                          continue

                     alerted_ips[ip] = severity

                     print("\n===================")
                     print("[HIGH ALERT]")
                     print("SSH Brute Force Detected")
                     print(f"Source IP: {ip}")
                     print(f"Attempts : {attempts}")
                     print("MITRE: T1110")
                     print(f"Confidence: {confidence}%")
                     print(f"Severity  : {severity}")
                     print("=================")
                     alert = {
                         "alert_id": generate_alert_id(),
                         "timestamp": datetime.now(IST).strftime(
                              "%Y-%m-%d %H:%M:%S IST"
                         ),
                         "type": "SSH Brute Force",
                         "ip": ip,
                         "confidence": confidence,
                         "severity": severity,
                         "review_status": "Pending"
                     }

                     save_alert(alert)

                     save_ioc(ip, "SSH Brute Force", severity, "T1110")
                     save_to_log(
                         BRUTEFORCE_LOG,
                         f"SSH Brute Force Detected - Source IP: {ip} Attempts: {attempts} Confidence:{confidence}% Severity:{severity} MITRE: T1110"
                     )


        # ── Privilege Escalation (T1078) ─────────────────────
        elif "sudo" in line and "COMMAND" in line:
            user_match = re.search(r'sudo:\s+(\S+)', line)
            cmd_match  = re.search(r'COMMAND=(.+)',  line)
            user = user_match.group(1) if user_match else "unknown"
            cmd  = cmd_match.group(1).strip() if cmd_match else line.strip()
            print(f"[CRITICAL] Privilege Escalation - User: {user} Command: {cmd}")
            save_ioc(user, "Privilege Escalation", "CRITICAL", "T1078")
            save_to_log(
                SUDO_LOG,
                f"Privilege Escalation - User: {user} Command: {cmd} MITRE: T1078"
            )

        # ── Account Creation (T1136) ──────────────────────────
        elif "new user" in line or "useradd" in line:
            print(f"[MEDIUM] Account Creation Detected: {line.strip()}")
            save_ioc("localhost", "Account Creation", "MEDIUM", "T1136")
            save_to_log(
                USER_LOG,
                f"Account Creation Detected: {line.strip()} MITRE: T1136"
            )


        # ── Successful Login (T1078 - Valid Accounts) ────────
        elif "Accepted password" in line or "Accepted publickey" in line:
            match = re.search(r'for (\S+) from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                user = match.group(1)
                ip   = match.group(2)
                now_ist = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")
                print(f"\n===================")
                print(f"[MEDIUM ALERT]")
                print(f"Successful Login Detected")
                print(f"User     : {user}")
                print(f"Source IP: {ip}")
                print(f"Time     : {now_ist}")
                print(f"MITRE    : T1078 - Valid Accounts")
                print(f"===================\n")
                save_ioc(ip, f"Successful Login - {user}", "MEDIUM", "T1078")
                save_to_log(
                    SUDO_LOG,
                    f"Successful Login - User: {user} Source IP: {ip} MITRE: T1078"
                )

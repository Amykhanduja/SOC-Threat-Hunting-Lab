# MITRE ATT&CK Mapping

## SSH Brute Force

Technique ID: T1110

Description:
Multiple failed SSH login attempts detected from the same source IP.

Evidence:
Failed password entries in auth.log.

Risk:
Credential guessing attack.

---

## Privilege Escalation

Technique ID: T1078

Description:
Use of sudo commands for elevated privileges.

Evidence:
COMMAND= entries in auth.log.

Risk:
Potential misuse of elevated permissions.

---

## Account Creation

Technique ID: T1136

Description:
New user account creation detected.

Evidence:
useradd entries in auth.log.

Risk:
Persistence mechanism by attacker.

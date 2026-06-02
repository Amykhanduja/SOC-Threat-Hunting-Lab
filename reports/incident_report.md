# Incident Investigation Report

## Incident 1: SSH Brute Force

Severity: High

MITRE ATT&CK:
T1110

Evidence:
9 failed SSH login attempts from 127.0.0.1

Impact:
Potential credential attack.

Recommendations:
- Enable MFA
- Enforce strong password policy
- Configure account lockout

---

## Incident 2: Privilege Escalation Activity

Severity: Medium

MITRE ATT&CK:
T1078

Evidence:
Multiple sudo command executions.

Impact:
Potential unauthorized privileged access.

Recommendations:
- Review sudo permissions
- Audit administrative actions

---

## Incident 3: Unauthorized Account Creation

Severity: Medium

MITRE ATT&CK:
T1136

Evidence:
Creation of user account "attacker"

Impact:
Potential persistence mechanism.

Recommendations:
- Investigate account owner
- Remove unauthorized accounts

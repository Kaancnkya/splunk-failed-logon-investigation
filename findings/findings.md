# Investigation Findings — Failed Logon Analysis

**Project:** Splunk Failed Logon Investigation — EventCode 4625
**Tool:** Splunk (Windows Security Event Log)
**Event:** EventCode 4625 — Failed Logon

---

## Summary

A targeted brute force attack was identified against a single Windows account. The attacker submitted repeated logon attempts using a known valid username but incorrect password, consistent with a credential-guessing campaign.

---

## Evidence

| Field | Value |
|-------|-------|
| Target Account | Henrique |
| Source IP | 127.0.0.1 *(lab environment — represents attacker IP in a real deployment)* |
| Failed Attempt Count | 25 |
| SubStatus | `0xC000006A` — correct username, wrong password |
| Time Window | Within 1 minute |
| LogonType | 3 (Network) |

---

## Attack Classification

**Targeted Brute Force**

SubStatus `0xC000006A` on every event confirms the attacker knew the account name. The high attempt count from a single source IP within a short time window is consistent with an automated credential attack.

This is distinct from account enumeration (`0xC0000064`), where an attacker probes for valid usernames. Here, the username was already known — the goal was the password.

---

## SOC Ticket (Draft)

```
Source IP:        127.0.0.1
Target Account:   Henrique
Event Count:      25
EventCode:        4625 (Failed Logon)
SubStatus:        0xC000006A (correct username, wrong password)
LogonType:        3 (Network)
Time Window:      [start timestamp] to [end timestamp]
Classification:   Targeted Brute Force

Next Step:        Check EventCode 4624 (Successful Logon) for the same source IP
                  to determine whether any attempt succeeded.
```

---

## What Was Not Investigated (Out of Scope — Version 1)

- EventCode 4624 correlation (successful logon check) — covered in next project
- Alert creation or threshold tuning
- Active Directory context or group membership of target account
- Kerberos pre-authentication failures (EventCode 4771)

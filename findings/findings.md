# Investigation Findings — Failed Logon Analysis

**Project:** Splunk Failed Logon Investigation — EventCode 4625
**Tool:** Splunk (Windows Security Event Log)
**Event:** EventCode 4625 — Failed Logon

---

## Summary

A high-volume failed logon pattern was identified against a single Windows account. The evidence is consistent with a targeted brute force attempt: one source IP, one target account, high event count within a short time window, and SubStatus 0xC000006A confirming the attacker used a valid username with incorrect passwords.

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

## Pattern Classification

**Consistent with: Targeted Brute Force**

SubStatus `0xC000006A` on every event indicates the attacker used a valid account name and repeatedly submitted incorrect passwords — the pattern associated with credential guessing against a known account.

This is distinct from account enumeration (`0xC0000064`), where an attacker probes for valid usernames. In enumeration, most SubStatus values would be `0xC0000064` (username does not exist), not `0xC000006A`.

> **Note:** In a real environment, pattern classification should be treated as a working hypothesis until corroborated with additional context (e.g., threat intelligence on the source IP, whether a successful logon followed, whether the account was newly created). In this lab, the events were generated under controlled conditions to demonstrate the pattern.

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
Pattern:          Consistent with Targeted Brute Force

Next Step:        Check EventCode 4624 (Successful Logon) for the same source IP
                  to determine whether any attempt succeeded.
```

---

## What Was Not Investigated (Out of Scope — Version 1)

- EventCode 4624 correlation (successful logon check) — covered in next project
- Alert creation or threshold tuning
- Active Directory context or group membership of target account
- Kerberos pre-authentication failures (EventCode 4771)

# Splunk Queries — Failed Logon Investigation (EventCode 4625)

> **Environment note:** These queries use field names confirmed in a Windows Server environment with Splunk Universal Forwarder and `sourcetype=WinEventLog:Security`. Field names can vary between Splunk versions and configurations. Always expand a raw event first to verify field names before querying.

> **Field names in this environment:**
> - Account name → `Account_Name` *(in some environments: `TargetUserName`)*
> - Source IP → `Source_Network_Address` *(in some environments: `IpAddress`)*
> - Failure code → `Sub_Status` *(in some environments: `SubStatus`)*

---

## Query 1 — Who is being targeted?

```spl
index=main EventCode=4625
| stats count by Account_Name
| sort -count
```

**What it does:** Counts failed logon attempts grouped by target account, sorted highest to lowest.
**What to look for:** An account with a count far above the rest is being specifically targeted.

---

## Query 2 — Where is the attack coming from?

```spl
index=main EventCode=4625
| stats count by Account_Name, Source_Network_Address
| sort -count
```

**What it does:** Adds source IP address to the count. Each row is a unique (account, IP) pair.
**What to look for:**
- One IP + one account + high count = brute force
- One IP + many accounts + low count per account = password spray

---

## Query 3 — What type of failure?

```spl
index=main EventCode=4625
| stats count by Account_Name, Source_Network_Address, Sub_Status
| sort -count
```

**What it does:** Adds Sub_Status to the previous query. Each row now tells you who, where, and why the logon failed.
**What to look for:** See Sub_Status reference table below.

---

## Sub_Status Reference

| Sub_Status Code | Meaning | Attack Implication |
|----------------|---------|-------------------|
| `0xC000006A` | Correct username, wrong password | Brute force — attacker knows the account is real |
| `0xC0000064` | Username does not exist | Enumeration — attacker is guessing account names |
| `0xC0000234` | Account is locked out | Lockout threshold was triggered |
| `0xC0000072` | Account is disabled | Misconfigured service or stale credentials |

---

## Optional: Convert Sub_Status from decimal to hex

If `Sub_Status` appears as a large decimal number (e.g. `3221225514` instead of `0xC000006A`):

```spl
index=main EventCode=4625
| eval Sub_Status=tostring(Sub_Status,"hex")
| stats count by Account_Name, Source_Network_Address, Sub_Status
| sort -count
```

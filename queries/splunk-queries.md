# Splunk Queries — Failed Logon Investigation (EventCode 4625)

All queries use `sourcetype="WinEventLog:Security"`. If your Splunk instance uses a different sourcetype, run `index=* EventCode=4625 | head 5` first to confirm the correct value.

> **Field name note:** Windows Security Event Logs use `TargetUserName`, not `user` or `username`. Using the wrong field name returns no results — this is a common beginner mistake.

> **SubStatus note:** SubStatus may appear as a decimal integer in some Splunk configurations. If you see a number like `3221225514` instead of `0xC000006A`, add `| eval SubStatus=tostring(SubStatus,"hex")` to any of the queries below.

---

## Query 1 — Who is being targeted?

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count by TargetUserName
| sort -count
```

**What it does:** Counts failed logon attempts grouped by target account, sorted highest to lowest.
**What to look for:** An account with a count far above the rest is being specifically targeted.

---

## Query 2 — Where is the attack coming from?

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count by TargetUserName, IpAddress
| sort -count
```

**What it does:** Adds source IP address to the count. Each row is a unique (account, IP) pair.
**What to look for:**
- One IP + one account + high count = brute force
- One IP + many accounts + low count per account = password spray

---

## Query 3 — What type of failure?

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count by TargetUserName, IpAddress, SubStatus
| sort -count
```

**What it does:** Adds SubStatus to the previous query. Each row now tells you who, where, and why the logon failed.
**What to look for:** See SubStatus reference table below.

---

## SubStatus Reference

| SubStatus Code | Meaning | Attack Implication |
|---------------|---------|-------------------|
| `0xC000006A` | Correct username, wrong password | Brute force — attacker knows the account is real |
| `0xC0000064` | Username does not exist | Enumeration — attacker is guessing account names |
| `0xC0000234` | Account is locked out | Lockout threshold was triggered |
| `0xC0000072` | Account is disabled | Misconfigured service or stale credentials |

---

## Optional: Convert SubStatus from decimal to hex

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| eval SubStatus=tostring(SubStatus,"hex")
| stats count by TargetUserName, IpAddress, SubStatus
| sort -count
```

**Use this if:** SubStatus appears as a large decimal number instead of a hex code in your results.

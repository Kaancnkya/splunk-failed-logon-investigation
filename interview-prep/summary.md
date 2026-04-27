# Interview Prep — Splunk Failed Logon Investigation

## 2-Minute Verbal Summary

*Use this when asked: "Walk me through a project in your portfolio."*

---

"I built a Splunk investigation project focused on Windows failed logon events — EventCode 4625.

The scenario was a SOC analyst receiving an alert about failed logon activity. I set up a Windows environment, generated controlled failed logon events using a network authentication loop, and investigated them in Splunk using three progressive queries.

The first query counted failed attempts by target account to identify who was being attacked. The second added source IP to determine where the traffic was coming from. The third added SubStatus — a hex code inside the event that tells you exactly why the logon failed.

SubStatus is the part most people skip. The code 0xC000006A means correct username, wrong password — that's a brute force. The code 0xC0000064 means the username doesn't exist — that's enumeration. Same EventCode, completely different threat. SubStatus is what separates them.

In my results, I found 25 failed attempts against one account from one IP, all with SubStatus 0xC000006A. I classified it as a targeted brute force and documented it in SOC ticket format.

The natural next step — which I'm covering in the follow-up project — is checking EventCode 4624 against the same IP to see whether any of those attempts succeeded."

---

## Expected Interview Questions

**Q: What is EventCode 4625?**
A: It's the Windows Security event logged every time a logon attempt fails. It covers failed logins from wrong passwords, wrong usernames, locked accounts, and disabled accounts.

**Q: What is SubStatus and why does it matter?**
A: SubStatus is a hex field inside the 4625 event that specifies the exact reason the logon failed. The two most important codes are 0xC000006A (correct username, wrong password — brute force) and 0xC0000064 (username does not exist — enumeration). Without SubStatus, you can count failures but you can't classify the attack type.

**Q: What is the difference between brute force and password spray?**
A: Brute force: one attacker IP, one target account, many attempts — the attacker knows the account is real and is guessing the password. Password spray: one attacker IP, many different accounts, one or two attempts each — the attacker tries a common password across many accounts to stay below lockout thresholds.

**Q: What field names does Windows use that beginners often get wrong?**
A: The target account field is `TargetUserName`, not `user` or `username`. If you search for the wrong name in Splunk, you get no results. It's easy to miss if you're used to other log formats.

**Q: What would you do after finding this brute force?**
A: First, correlate EventCode 4625 (failed) with EventCode 4624 (successful logon) for the same source IP and time window — to check if any attempt succeeded. If there's a successful logon from that IP after the failed attempts, that's a confirmed compromise. Then I'd check what the account did after login.

**Q: What would you do differently if you ran this project again?**
A: I'd add a time chart (`timechart`) query to visualize the spike in failures over time — it's easier to show in a ticket than a raw count table. I'd also add LogonType to the investigation to separate interactive logins (Type 2) from network logins (Type 3).

---

## Key Terms to Know

| Term | Definition |
|------|-----------|
| EventCode 4625 | Windows Security event for failed logon |
| EventCode 4624 | Windows Security event for successful logon |
| SubStatus | Hex field indicating specific reason logon failed |
| TargetUserName | Field name for the account that was targeted |
| LogonType 3 | Network logon (remote connection, net use) |
| Brute force | Repeated attempts against one known-valid account |
| Password spray | One attempt per account across many accounts |
| Account enumeration | Probing for valid usernames using 0xC0000064 pattern |

# DET-CREDACCESS-001: SSH Password Spray Detection

A detection engineering project implementing a custom Wazuh ruleset to detect SSH password spraying with kill chain escalation. Built from scratch in a homelab environment - including ideation, baselining, rule development, iterative debugging, and validation.

## What This Detects

Standard brute-force SIEM rules trigger on repeated failures against the **same user**. Password spraying deliberately avoids this by attempting **one password per user across many accounts** - staying below lockout thresholds and evading naive detection.

This project builds two detections:

**Rule 100101 — Password Spray (Level 12/High)**
> Single source IP attempts authentication against 6+ distinct usernames within 10 minutes, with ≤1 attempt per user.

**Rule 100104 — Spray + Credential Access (Level 15/Critical)**
> Spray detected (100101) AND successful login from the same IP within 5 minutes → likely credential access achieved.

```
SSH Failures (5710/5716)
        ↓
   100100: Tag "Failed password" events only
        ↓
   100101: Same IP, 6+ distinct users, 600s → Level 12
        ↓
   100102: Suppress re-fires
        
SSH Success (5715)
        ↓
   100104: 100101 fired + success from same IP within 300s → Level 15 CRITICAL
```

**MITRE ATT&CK**
---
- T1110.003 — Password Spraying
- T1078 — Valid Accounts (escalation only)




## Lab Setup

| Component | Detail |
|---|---|
| Attacker | Windows 11 Host → Golang fuzzer |
| Victim/Agent | Ubuntu 25.x VM, Wazuh Agent 001 |
| SIEM | Wazuh 4.14.1 (headless Ubuntu Server) |
| Log Source | systemd journald → Wazuh |
| Target Accounts | 13 users (mix of valid/invalid), 1 planted valid credential |


## Deployment

```bash
# Copy rules to Wazuh
cp rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml

# Validate XML
xmllint --noout /var/ossec/etc/rules/local_rules.xml && echo "OK"

# Reload
sudo /var/ossec/bin/ossec-control reload

# Confirm rules loaded
grep -E "100100|100101|100104" /var/ossec/logs/ossec.log | tail -5

# Live monitoring
tail -f /var/ossec/logs/alerts/alerts.log | grep -E "100101|100104"
```


## Attack Simulation

The fuzzer is a Golang SSH client that iterates a username wordlist, attempting one password per user sequentially. Valid credential is placed last to ensure spray threshold triggers before success.

```bash
# Run from attacker machine
go run fuzzer/fuzzer.go

# Expected output
Processing: roy
Failed for roy: ...
Processing: shreya
Failed for shreya: ...
...
Processing: svc_backup
SUCCESS for svc_backup!
```

**Expected alert sequence:**
1. Rule 100101 fires at 6th distinct user → Level 12 alert in Wazuh dashboard
2. Rule 100104 fires after `svc_backup` succeeds → Level 15 CRITICAL alert



## Key Engineering Decisions

**Why `<match>Failed password</match>` on rule 100100:**
Ubuntu sshd emits two lines per invalid user attempt (`Invalid user X` + `Failed password`). Without this filter, one user = two events, causing the spray rule to fire early with incorrect count.

**Why `ignore="300"` is an attribute, not a child element:**
Wazuh 4.x silently ignores `<ignore>` as a child element on correlation rules. Must be `<rule id="..." ignore="300">`. Spent a debugging cycle on this.

**Why valid credential must be last in wordlist:**
Rule 100104 looks backward in the event buffer for 100101 when a 5715 (success) fires. If success fires before 100101 is registered, the correlation window misses it. Wordlist ordering is a deployment requirement for testing.

**Why `<same_source_ip />` is deprecated:**
Wazuh 4.x uses `<same_srcip />`. The old tag may silently fail.


## Known Detection Gaps

| Gap | Impact |
|---|---|
| Distributed spray (1–3 users per IP, many IPs) | Not detected — no per-IP threshold breach |
| Slow spray (>10 min between attempts) | Missed — exceeds 600s window |
| Cross-host spray (same IP, multiple servers) | Not detected — no cross-agent correlation |
| Valid credential placed early in wordlist | 100104 misses — success fires before 100101 |
| Spray via protocol other than SSH | Out of scope |


## Detection Spec

Full 14-section detection specification including MITRE mapping, log requirements, threshold rationale, false positive analysis, and response guidance: [`detection.md`](detection.md)

Full iterative changelog of every bug, fix, and design decision: [`rule_evolution.md`](rule_evolution.md)



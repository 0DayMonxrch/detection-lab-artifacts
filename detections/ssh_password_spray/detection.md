# Detection Specification
## SSH Password Spray Detection with Credential Access Escalation



## Detection Metadata

| Field | Value |
|---|---|
| **Detection ID** | DET-CREDACCESS-001 |
| **Detection Name** | SSH Password Spray with Credential Access Escalation |
| **Version** | 1.0 |
| **Author** | Dibyadipan |
| **Date Created** | 2026-02-22 |
| **Last Updated** | 2026-02-22 |
| **Status** | Improvising |
| **Platform** | Linux / Ubuntu 25.x |
| **SIEM** | Wazuh 4.14.x |


## 2. Objective / Detection Goal

To detect SSH password spraying activity where a single source IP attempts authentication against multiple distinct accounts using one attempt per user - a pattern specifically designed to evade standard brute-force detections. A secondary escalation rule fires when a spray attempt is followed by a successful login from the same source IP within a defined time window, confirming likely credential access.

**Risk Mitigated:** Undetected initial access via valid credential compromise on SSH-exposed endpoints. Standard brute-force rules (repeated failures on same user) are blind to this pattern by design.


## 3. Threat Context

A threat actor performs a low-and-slow SSH password spray against an internal Linux host. The attack uses a curated wordlist of usernames gathered via OSINT or internal enumeration - targeting known service accounts, default accounts, and human accounts simultaneously. The spray is deliberately spread across 10-20 minutes to avoid triggering rate-based lockout mechanisms and to stay below the threshold of naive failure-count SIEM rules.

The attacker uses a custom automation script (in this scenario, a Golang binary) that iterates over a username list, attempting a single SSH password authentication per user with a common or leaked password, then moves on regardless of outcome. This pattern - one attempt per user - is the defining behavioral signature.

**Real-World Relevance:**
- APT initial access against VPN gateways and SSH bastions
- Ransomware operators performing lateral movement after initial foothold
- Credential stuffing adapted for internal SSH environments
- Cloud identity abuse (Azure AD, AWS IAM adapted variants)

**Known Tools:** Hydra (`-l` list mode), Medusa, CrackMapExec (`--no-bruteforce`), Metasploit `ssh_login` with user list, custom scripts (Go, Python).



## 4. MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Sub-Technique | ID |
|---|---|---|---|---|
| Primary | Credential Access | Brute Force | Password Spraying | T1110.003 |
| Follow-on | Initial Access / Lateral Movement | Valid Accounts | -- | T1078 |

The T1078 mapping applies only when Rule 100104 fires (spray + success correlation). Rule 100101 alone maps to T1110.003 only.



## 5. Log & Telemetry Requirements

**Log Source:** Linux `sshd` via systemd journal (`journald`)

**Log Pipeline:** `journald → Wazuh Agent (001) → Wazuh Manager → OpenSearch`

**Relevant Wazuh Base Rule IDs:**

| Rule ID | Description | Maps To |
|---|---|---|
| 5710 | Failed password for invalid user | Spray candidate |
| 5716 | Failed password for valid user | Spray candidate |
| 5715 | Authentication success | Post-spray escalation trigger |

**Required Fields per Event:**

| Field | Source | Purpose |
|---|---|---|
| `srcip` | sshd decoder | Correlation anchor |
| `srcuser` / `dstuser` | sshd decoder | Distinct user tracking |
| `timestamp` | predecoder | Timeframe window evaluation |
| `program_name` | predecoder | sshd-session filter |

**Known Decoder Behavior (Ubuntu 25.x):**
- Invalid users: sshd emits two log lines - `Invalid user X from IP` and `Failed password for invalid user X from IP`. Only the `Failed password` line should be consumed by correlation (enforced via `<match>Failed password</match>` on the tagging rule).
- Valid users: single `Failed password for X from IP` line.
- Successful auth: `Accepted password for X from IP` - decoded by Wazuh as rule 5715, tagged as `syslog,sshd,authentication_success`.
- Username field inconsistency: valid user failures map to `dstuser`; invalid user failures map to `srcuser`. The correlation engine handles both.

**Log Retention Assumption:** Minimum 7 days for alert index. Wazuh correlation operates on in-memory sliding windows only - no historical correlation across agent restarts.


## 6. Detection Strategy

**Behavioral Pattern:** A single source IP performs authentication attempts against N distinct usernames within a defined time window, with no more than one attempt per username. The absence of repeated attempts per user is the primary differentiator from brute force.

**Baseline Assumption:** In this internal lab environment, 2–4 failed SSH logins from a single IP within any 10-minute window represents normal administrative or user error behavior. Threshold is set at 6 distinct users to sit well above this baseline while remaining sensitive enough to catch conservative sprays.

**Time Window Logic:** A 600-second (10-minute) sliding window is used. The attacker's spray in this scenario spans ~90 seconds in lab conditions; the window provides sufficient headroom for real-world slow sprays while avoiding excessively long windows that accumulate false positives from unrelated events.

**Aggregation Strategy:** Events are aggregated by `srcip` + `distinct_user`. The correlation engine counts unique `srcip`+`user` pairs within the window. When the count reaches the threshold (6), the spray rule fires. A second rule monitors for a successful login (`rule 5715`) from the same source IP within 300 seconds of the spray detection, escalating severity if found.

**Why This Catches What Brute Force Rules Miss:** Standard brute force rules trigger on repeated failures for the same user (same user, high frequency) or on total failure count (high volume). Password spray is low volume per user and spreads across many users — neither condition is met. The `different_user` constraint in the correlation rule is the key primitive.

---

## 7. Detection Logic (Implementation)

### Pseudocode

```
FOR each SSH auth failure event:
    tag event IF log line contains "Failed password"
    
    IF count(tagged events WHERE srcip = X AND user != previous_user) >= 6
    WITHIN 600 seconds:
        FIRE alert: "Password Spray Detected" @ level 12
        
        IF SSH success event (rule 5715) fires WHERE srcip = X
        WITHIN 300 seconds of spray alert:
            FIRE alert: "Spray + Credential Access" @ level 15
```

### Wazuh XML Rules

```xml
<group name="syslog,sshd,custom_spray,">

  <!-- 100100: Tag SSH auth failures (Failed password line only) -->
  <rule id="100100" level="3">
    <if_sid>5710,5716</if_sid>
    <description>SSH authentication failure - tagged for spray correlation</description>
    <group>authentication_failure,ssh_spray_candidate,</group>
  </rule>

  <!-- 100101: Spray detection - 6 distinct users from same IP within 600s -->
  <rule id="100101" level="12" frequency="6" timeframe="600" ignore="300">
    <if_matched_sid>100100</if_matched_sid>
    <same_srcip />
    <different_user />
    <description>Possible SSH password spray: $(srcip) attempted login against 6+ distinct users within 10 mins</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>authentication_failures,password_spray,attack,</group>
  </rule>

  <!-- 100102: Suppress re-fires from same IP within suppression window -->
  <rule id="100102" level="0" timeframe="600">
    <if_matched_sid>100101</if_matched_sid>
    <same_srcip />
    <description>Suppressing duplicate spray alert from same source IP</description>
    <options>no_log</options>
  </rule>

  <!-- 100104: Tag 100101 firing as spray-confirmed -->
<rule id="100104" level="15" timeframe="300" ignore="300">
  <if_matched_sid>100101</if_matched_sid>
  <if_sid>5501</if_sid>
  <!--<same_srcip />-->
  <description>CRITICAL: SSH password spray followed by successful login!</description>
  <mitre>
    <id>T1110.003</id>
    <id>T1078</id>
  </mitre>
  <group>password_spray,credential_access,attack,critical,</group>
</rule>

</group>
```


## 8. Threshold Rationale

**Threshold: 6 distinct users / 600 seconds**

**Lab Baseline Observation:** During normal lab operation with 13 password-enabled user accounts, the maximum observed failed login count from a single IP in any 10-minute window was 2–3 (manual typos, misconfigured SSH client). Threshold of 6 sits 2x above this baseline with margin.

**Expected User Behavior:** A legitimate user retrying SSH will fail on the same username repeatedly — not across 6 different accounts. Multi-account failures from the same IP in a short window have no legitimate explanation in this environment outside of automation.

**Risk Tolerance:** Set conservatively low for a controlled internal environment with no internet-facing exposure. In production internet-facing SSH, threshold should be raised to 10–15 and combined with GeoIP external-only filtering to avoid botnet-induced alert fatigue.

**SOC Capacity Consideration:** At this threshold in a lab with one agent, expected alert volume is 0 in normal operation, triggering only on active attack simulation. In production, aggressive tuning (allow-listing known scanner IPs, raising threshold) would be required before deployment.


## 9. Validation & Testing

### 9.1 Test Environment

| Component | Detail |
|---|---|
| Attacker Machine | Windows 11 Host (VMware NAT, 192.168.17.1) |
| Victim/Agent | Ubuntu 25.x VM (192.168.17.130), Wazuh Agent 001 |
| SIEM Manager | Ubuntu Server (headless), Wazuh 4.14.1 |
| Log Pipeline | journald → Wazuh Agent → Manager → OpenSearch |
| Fuzzer | Custom Golang SSH fuzzer (sequential, 1 attempt per user) |
| Target Accounts | 13 users (mix of valid and invalid), 1 known-valid credential |

### 9.2 Attack Simulation

**Tool:** Custom Golang SSH fuzzer

**Wordlist (ordered — valid credential placed last to ensure spray fires before success):**
```
roy, shreya, admin, rohit, dev, hitesh, sarah, svc_backup (valid)
```

**Behavior:** Sequential SSH password attempts, ~7–10 seconds apart, single goroutine, exits on success and continues on failure.

**Expected Telemetry:**
- 7 × `Failed password` events → triggers rules 5710 / 5716 → tagged by 100100
- 1 × `Accepted password` event → triggers rule 5715 → tagged by 100103
- Rule 100101 fires at 6th distinct user (level 12)
- Rule 100104 fires when 5715 arrives within 300s of 100101 (level 15)

### 9.3 Detection Outcome

| Rule | Expected | Observed | Notes |
|---|---|---|---|
| 100100 | Tags each failure | Confirmed | `Failed password` filter prevents double-count |
| 100101 | Fires at 6th user, level 12 | Confirmed | `srcip` correctly populated in alert |
| 100102 | Suppresses re-fires | Confirmed | `no_log` at level 0 |
| 100103 | Tags success event | Confirmed | Fires via rule 5715 |
| 100104 | Fires after spray+success, level 15 | Confirmed | Requires valid credential last in wordlist |

**Alert Quality:** High. Alerts carry `srcip`, `previous_output` (last 5 correlated events), MITRE tags, and severity level appropriate for automated escalation.

**Edge Cases Observed During Testing:**
- `Invalid user X` pre-auth line caused early firing (fixed via `<match>Failed password</match>`)
- 5715 firing before 100101 when valid user was mid-wordlist (fixed by wordlist ordering)
- PAM decoder capturing `Accepted password` as rule 5501 (resolved — 5715 fires for sshd events; 5501 fires for PAM session events separately)
- `<ignore>` as child element vs attribute — Wazuh 4.x requires it as rule attribute

---

## 10. False Positive Analysis

**Legitimate Administrative Activity:** An admin SSHing into multiple servers as different service accounts from the same jump host could trigger 100101. Mitigation: add known admin IP ranges to a suppression list.

**Automated Service Accounts:** IAM sync tools, Ansible, or configuration management systems that authenticate as multiple users in short succession. In production these IPs should be allow-listed. Estimated risk: Medium in environments with heavy automation.

**Misconfigured Applications:** A misconfigured monitoring script cycling through account health checks. Estimated risk: Low in controlled environments, Medium in enterprise.

**Load Testing Scenarios:** Security assessment tools or load testers probing authentication endpoints. If red team exercises are scheduled, suppress 100101 for the duration.

**Developer Environments:** Dev teams iterating account setups on shared infrastructure could trigger. Rule should be scoped to production bastion hosts only in production deployments.

**Estimated False Positive Risk:** Low (lab), Medium (production without tuning)


## 11. Tuning & Optimization Strategy

**Field Exclusions:**
```xml
<!-- Suppress known internal scanner IPs -->
<rule id="100105" level="0">
  <if_sid>100101</if_sid>
  <srcip>10.10.10.100</srcip>  <!-- known vulnerability scanner -->
  <description>Suppressing spray alert from known internal scanner</description>
  <options>no_log</options>
</rule>
```

**Threshold Adjustments for Production:**
- Internet-facing SSH: raise to 10–15 distinct users, add `<not_same_src_ip>` GeoIP internal-only filter
- Internal-only environment: current threshold of 6 is appropriate
- High-noise environment: raise timeframe to 1200s, raise threshold to 12

**Service Account Allow-listing:** Tag known service account source IPs and exclude them from 100100 tagging entirely to prevent them entering the correlation pipeline.

**GeoIP Enrichment (Future):** Add GeoIP decoder to flag external source IPs. Spray from an external IP is higher severity than from an internal host. Separate rule levels: external spray = 14, internal spray = 12.

**Time-Based Suppression:** During business hours, human multi-account errors are more likely. Consider raising threshold by 2 during 09:00–18:00 local time if false positive rate is high post-deployment.


## 12. Detection Coverage & Gaps

**What This Detection Does NOT Catch:**

| Gap | Description | Bypass Method |
|---|---|---|
| Distributed spray | Multiple IPs each trying 2–3 users - never hits per-IP threshold | Botnet with 3 users per IP, rotate |
| Very slow spray | 1 attempt per user every 20+ minutes - exceeds 600s window | Spray over 6+ hours |
| Cross-host spray | Same IP spraying 3 different SSH servers - no cross-agent correlation | Spread attempts across targets |
| Protocol hop | Spray via FTP, HTTP basic auth, or web login forms | Switch protocol |
| Key-based spray | Auth via key enumeration - no password failure events | Use key-based auth methods |
| Post-compromise internal spray | Compromised host with internal IP - may be on allow-list | Use trusted internal host as pivot |

**Logging Blind Spots:**
- `sshd-session` vs `sshd` program name variance across Linux distros — decoder must handle both
- MaxAuthTries reached silently — sshd may stop logging after N failures depending on config
- Spraying via SSH certificates — no password failure events generated

**Wazuh Engine Limitations Discovered:**
- No long-term memory — correlation state is in-memory only, lost on manager restart
- Sliding window re-fires require `ignore` attribute to suppress; `<ignore>` as child element is invalid in 4.x
- `frequency` attribute minimum value is 2; `frequency="1"` is a schema error
- `<same_source_ip />` is deprecated in 4.x — use `<same_srcip />`
- `if_matched_sid` + `if_sid` correlation requires the `if_sid` event to be the current triggering event; the `if_matched_sid` looks backward in the correlation buffer

---

## 13. Severity & Response Guidance

**Rule 100101 — Level 12 (High): Password Spray Detected**

Triage Checklist:
1. Confirm `srcip` — internal or external?
2. Check `previous_output` for targeted usernames — any privileged accounts (root, admin, svc_*)?
3. Verify no 100104 escalation within 5 minutes
4. Check if `srcip` is a known asset (scanner, admin host, automation)
5. Review auth.log for the window ±5 minutes around the alert timestamp

Immediate Containment:
- Block `srcip` at host firewall if external: `ufw deny from <srcip>`
- Rotate credentials for all targeted accounts as precaution
- Notify account owners if human accounts were targeted

Escalation Path: If 100104 fires → immediate incident response. Assume credential compromised.

**Rule 100104 — Level 15 (Critical): Spray + Credential Access**

Triage Checklist:
1. Identify which user authenticated successfully (check `User` field in alert)
2. Determine what the user account has access to — is it privileged?
3. Check for subsequent commands or session activity: `journalctl _UID=$(id -u <user>)`
4. Check for lateral movement indicators from the same IP against other hosts

Immediate Containment:
- Lock compromised account immediately: `passwd -l <username>`
- Kill active sessions: `pkill -u <username>`
- Isolate host from network if compromise is confirmed
- Preserve forensic artifacts before remediation

Escalation Path: Escalate to incident response team. Open incident ticket. Preserve `/var/log/auth.log` and journald export for forensic analysis.

---

## 14. Metrics & KPIs (Lab Estimates)

| Metric | Value | Notes |
|---|---|---|
| **Mean Time to Detect (MTTD)** | ~60–90 seconds | Time from first spray attempt to 100101 alert |
| **Alert Volume (lab)** | 1 alert per test run | With `ignore="300"` suppression |
| **False Positive Rate (lab)** | 0% | Controlled environment, no legitimate multi-account activity |
| **Detection Confidence** | High | Rule fires consistently on threshold breach |
| **Escalation Rate** | 100% when valid cred in wordlist | Dependent on attacker having a valid credential |
| **Rule Chain Depth** | 5 rules (100100–100104) | Each adds a specific detection primitive |

**Detection Confidence Caveat:** Confidence is High for the exact simulated scenario. Against distributed or slow sprays (see Coverage Gaps), confidence drops to Low without supplementary detections.

---

## 15. Rule Evolution Notes

See `rule_evolution.md` for a full changelog of design decisions, bugs encountered, and iterative fixes applied during development and testing.

---

## 16. Future Improvements (v2 Backlog)

1. **Cross-host correlation** — same source IP spraying multiple agents within the same timeframe → escalate to campaign-level alert
2. **Privileged user targeting flag** — separate rule tracking spray attempts specifically against root, admin, svc_* accounts → higher severity
3. **Threat intel enrichment** — correlate `srcip` against known bad IP feeds (AbuseIPDB, Shodan) at alert time
4. **GeoIP tiering** — external IP spray = higher severity than internal
5. **Distributed spray detection** — aggregate by target host + timeframe, flag coordinated multi-IP campaigns
6. **Active response integration** — auto-block `srcip` via Wazuh active response on 100104 trigger

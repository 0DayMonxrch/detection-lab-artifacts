# Rule Evolution Log
## DET-CREDACCESS-001 — SSH Password Spray Detection

This document tracks every iteration of the detection rule from initial design through validation. It exists to demonstrate engineering process - not just the final output. Every change was driven by an observable failure, a discovered limitation, or a deliberate design decision.


## v0.1 Initial Design (Pre-Implementation)

**Design Decisions:**
- Detection hypothesis: single `srcip`, ≥6 distinct usernames, within 600s, ≤1 attempt per user
- Chose Wazuh correlation primitives: `<same_srcip />`, `<different_user />`, `<frequency>`, `<timeframe>`
- Base rules identified: 5710 (invalid user failure), 5716 (valid user failure)
- Threshold set at 6 based on lab baseline of 2–4 max legitimate failures per window

**Initial Rule Structure:**
```xml
<rule id="100010" level="3">
  <if_sid>5710,5716</if_sid>
  <description>SSH authentication failure - tagged for spray correlation</description>
  <group>authentication_failure,ssh_spray_candidate,</group>
</rule>

<rule id="100011" level="12">
  <if_matched_sid>100010</if_matched_sid>
  <same_source_ip />
  <different_user />
  <frequency>6</frequency>
  <timeframe>600</timeframe>
  <description>Possible SSH Password Spray</description>
</rule>
```


## v0.2 Field Discovery: `srcuser` vs `dstuser`

**Problem:** During `wazuh-logtest` validation, the decoded username field was `srcuser`, not `dstuser` as initially assumed.

**Root Cause:** Wazuh's sshd decoder maps the username from inbound SSH auth failures to `srcuser` (the user the attacker claims to be), not `dstuser`. This is semantically correct — in the context of inbound SSH, the claimed username is the source user.

**Impact on Rules:** `<different_user />` in Wazuh correlation tracks `srcuser` internally — no rule change required. Impact was cosmetic only (description placeholder `$(dstuser)` would not resolve).

**Fix:** Removed `$(dstuser)` placeholder from description. Used static description text since Wazuh does not support runtime interpolation of `freq` or `timeframe` values in descriptions. `srcip` is correctly carried in the alert JSON regardless.

**Note:** Inconsistency observed between valid and invalid user events:
- Invalid user failures → `srcuser` field
- Valid user failures → `dstuser` field

This is a decoder normalization gap in Wazuh's built-in sshd decoder. Both fields are checked by `<different_user />` — detection is unaffected.


## v0.3 Duplicate Alert Problem: Sliding Window Re-fires

**Problem:** 8-user spray wordlist produced 2 alerts (fired at user 6, then again at user 8).

**Root Cause:** Wazuh's correlation engine uses a sliding window — after the threshold is met and the rule fires, the window remains open. Each new matching event that arrives continues to satisfy the frequency condition, causing repeated alerts.

**Attempted Fix 1:** `<ignore>300</ignore>` as child element → had no effect.

**Why it failed:** `<ignore>` as a child element is invalid in Wazuh 4.x for correlation rules. It is interpreted as unknown XML and silently ignored.

**Attempted Fix 2:** Suppression child rule (rule 100102) with `<options>no_log</options>`.

**Why it partially worked but was insufficient:** `no_log` suppresses logging but the correlation engine still processed the re-fire events. Additionally, `firedtimes` incrementing on the parent rule (100101) meant rule 100102's `if_matched_sid` was matching a "new" fire context each time.

**Final Fix:** `ignore="300"` as an **attribute** on the `<rule>` tag:
```xml
<rule id="100101" level="12" frequency="6" timeframe="600" ignore="300">
```

`ignore` as an attribute correctly throttles the rule from re-firing from the same source within 300 seconds.

**Lesson:** Wazuh's `ignore` is an attribute, not a child element. The documentation is ambiguous on this point.


## v0.4 Double-Counting: Invalid User Pre-Auth Lines

**Problem:** Rule 100101 was firing at the 5th event instead of the 6th.

**Root Cause:** Ubuntu's sshd (and `sshd-session` in Ubuntu 25.x) emits **two log lines** for each invalid user authentication attempt:
```
Invalid user roy from 192.168.17.1 port 44670
Failed password for invalid user roy from 192.168.17.1 port 44670 ssh2
```

Both lines matched rule 5710 and were tagged by rule 100100, counting one physical user as two correlation events. This inflated the count and caused early firing.

**Fix:** Added `<match>Failed password</match>` to rule 100100:
```xml
<rule id="100100" level="3">
  <if_sid>5710,5716</if_sid>
  <match>Failed password</match>
  ...
</rule>
```

This ensures only the definitive `Failed password` line enters the correlation pipeline. The `Invalid user X` pre-auth line passes through rule 5710 but never reaches 100100 or the correlation window.

**Lesson:** Always audit what log lines a base rule actually matches, not just what it's documented to match. Double-emit patterns are common in sshd across Linux distributions.


## v0.5 Spray + Success Escalation Rule (100104): First Attempt

**Design:** Add a second-stage rule to escalate severity when a successful login follows a spray from the same IP within 5 minutes.

**Initial Approach:**
```xml
<rule id="100104" level="15" timeframe="300">
  <if_matched_sid>100101</if_matched_sid>
  <same_srcip />
  <match>Accepted password</match>
</rule>
```

**Why it failed:** `<if_matched_sid>` + `<match>` cannot co-exist as intended. `if_matched_sid` anchors to rules that are children of the matched rule's chain. `Accepted password` events pass through rule 5715 — a completely separate decoder chain from 100100→100101. Wazuh never evaluates 100104 for the success event because it's not in the right chain context.

**Lesson:** In Wazuh, `if_matched_sid` looks for events that were previously processed under that rule ID. The current triggering event must be the `if_sid` match. The historical event is the `if_matched_sid`. These two are not interchangeable.


## v0.6 Spray + Success Escalation: Correct Approach

**Fix:** Restructured 100104 to use `if_sid` (current event = 5715 success) and `if_matched_sid` (historical = 100101 spray):

```xml
<rule id="100104" level="15" timeframe="300">
  <if_matched_sid>100101</if_matched_sid>
  <if_sid>5715</if_sid>
  <same_srcip />
  ...
</rule>
```

**Why this works:** When a 5715 (success) event arrives, Wazuh evaluates all rules with `<if_sid>5715</if_sid>`. Rule 100104 matches because it has `if_sid>5715`. Wazuh then checks if `if_matched_sid>100101` fired from the same `srcip` within the last 300 seconds — if yes, fires the escalation.

**Still not firing** — proceeded to further debug.



## v0.7 PAM Decoder Interference Discovery

**Problem:** Rule 100104 still not firing despite correct structure.

**Investigation:** Checked which rules were actually firing for the success event:
```
Rule: 5502 (level 3) -> 'PAM: Login session closed.'
Rule: 5501 (level 3) -> 'PAM: Login session opened.'
```

**Root Cause:** Ubuntu 25.x with `sshd-session` as the process name causes the PAM decoder to win the decoding race for session-related events. `Accepted password` was being decoded by both the sshd decoder (→ 5715) AND triggering PAM events (→ 5501/5502). Investigated 5501 as alternative anchor — but `srcip` is absent from PAM events since they're process-local.

**Resolution:** Confirmed via `grep "Rule: 57"` on alerts.log that 5715 WAS firing 9 times. The issue was not decoder interference — it was event ordering.


## v0.8 Root Cause Confirmed: Event Ordering (5715 Fires Before 100101)

**Problem:** Grep on alerts.log revealed consistent pattern:
```
Rule: 5715  ← success fires FIRST
Rule: 100101 ← spray detected AFTER
```

**Root Cause:** `svc_backup` (the valid credential) was the 7th entry in the wordlist. At the time the success event arrived, only 5–6 invalid user events had been processed. Due to the double-line emission and `ignore` attribute interaction, 100101 hadn't fired yet when 5715 arrived. By the time 100101 fired (on the failure of user 8, sarah), the 5715 event was already outside the 300s lookback window — or more precisely, 100104's `if_matched_sid` buffer didn't contain 100101 yet when 5715 arrived.

**Fix:** Moved `svc_backup` (valid credential) to **last position** in the wordlist:
```
roy, shreya, admin, rohit, dev, hitesh, sarah, svc_backup
```

This guarantees: 7 failures → 100101 fires → svc_backup attempt → 5715 fires within seconds → 100104 escalates.

**Architectural Note:** This ordering dependency is a real-world consideration. An attacker who places the valid credential early in their list would evade 100104 in this implementation. Documented as a known limitation.



## v1.0 Production-Ready Ruleset

**Final state:** All 5 rules functioning as designed.

| Rule | Function | Level |
|---|---|---|
| 100100 | Tag `Failed password` events | 3 | 
| 100101 | Spray detection (6 users / 600s) | 12 | 
| 100102 | Suppress re-fires | 0 | 
| 100103 | Tag successful logins | 3 |
| 100104 | Spray + success escalation | 15 |

**Validation confirmed:**
- 100101 fires at 6th distinct user 
- 100101 does not re-fire within 300s `ignore` window 
- 100104 fires within seconds of 5715 following 100101 
- Single alert per attack cycle in both rule 100101 and 100104 
- MITRE tags (T1110.003, T1078) present in alert JSON 
- `mail: true` on level 12+ for alerting 

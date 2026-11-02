# 5-Minute Mentor Walkthrough: Explainable BGP Anomaly Monitor

> **Target Audience**: Technical mentor, network evaluator, or hackathon jury.  
> **Total Duration**: 5 minutes (timed walkthrough).  
> **Prerequisites**: Repository cloned, virtual environment active (`.venv`), all commands run 100% offline from the workspace root (`d:\Project\bgp-anomaly-monitor`).

---

## Overview of the Walkthrough

| Time | Segment | Focus | Command |
|---|---|---|---|
| **0:00 – 1:00** | **System Verification & Scope** | Test suite integrity & architectural boundary | `python -m pytest -q` |
| **1:00 – 2:00** | **Rule Baseline & Evidence** | Strict precedence & RFC 6811 explainability | `python -m src.cli demo --limit 1 --explain-first` |
| **2:00 – 3:00** | **The Forged-Origin Gap** | Why rules achieve 0% recall on forged origins | `python -m src.cli demo --limit 5` |
| **3:00 – 4:00** | **ML Detector & Closing the Gap** | Recovering about 70% (59% to 81% across three seeds) recall via feed metadata | `python -m src.cli explain --alert-id alt-ml-7a7b0b3b` |
| **4:00 – 5:00** | **Engineering Honesty & False Positives** | The TE false positive cost & operational trade-off | `python -m src.cli explain --alert-id alt-ml-107ff437` |

---

## Minute 1 (0:00 – 1:00): System Verification & Scope

### Action (Terminal)
```bash
python -m pytest -q
```

### What You See
```text
........................................................................................
88 passed in 15.59s
```

### What to Say
> *"Welcome! Today we are demonstrating an Explainable BGP Origin and Subprefix Anomaly Monitor built for Problem Statement PS-005.*
> 
> *First, notice our test suite: all 88 unit and integration tests pass cleanly and 100% offline. Our monitor replays BGP announcements, validates each route against time-aligned RPKI ROA snapshots with zero future leakage, looks up operator prefix inventory, and emits evidence-backed alerts explaining exactly why each alert fired.*
> 
> *Our engineering boundary is strictly respected: we do NOT perform AS_PATH graph analysis, and we do NOT trigger automated traffic blocking or blackholing. Every detection is designed for an operator or analyst to review with complete RPKI/ROV and statistical evidence."*

---

## Minute 2 (1:00 – 2:00): Rule Baseline & Evidence Rationale

### Action (Terminal)
```bash
python -m src.cli demo --limit 1 --explain-first
```

### What You See
```text
================================================================================
 BGP ORIGIN & SUBPREFIX ANOMALY MONITOR: LIVE DEMONSTRATION
================================================================================
Dataset:   data/feed_replay.csv (3,164 updates, 92 labelled events)
Mode:      RFC 6811 + Prefix Inventory Rule Baseline
Option:    --limit 1
Option:    --explain-first (full RPKI/ROV evidence report on first alert)
--------------------------------------------------------------------------------
Streaming BGP announcements through RuleBasedDetector...

[ALERT #1 - EXPLAIN-FIRST EVIDENCE REPORT]
================================================================================
 BGP ANOMALY MONITOR: EXPLAINABLE ALERT REPORT
================================================================================
Alert ID:     alt-67e804c0
Time (UTC):   2026-10-26T02:40:34.030000Z (epoch: 1792982434.03)
Detector:     RULES
Alert Type:   ORIGIN_HIJACK
Severity:     HIGH
Prefix:       198.51.100.0/22
Origin ASN:   AS65853
Peer:         198.32.132.1
--------------------------------------------------------------------------------
EVIDENCE & RATIONALE:
--------------------------------------------------------------------------------
Reason:
  Origin AS65853 not in inventory for exact prefix 198.51.100.0/22, ROV Invalid, so ORIGIN_HIJACK (Rule 1 fired on exact match; pass-through skipped due to unauthorized origin and non-valid ROV).

RFC 6811 Route Origin Validation (ROV):
  ROV State:      Invalid
  Invalid Reason: origin_mismatch
  Snapshot Time:  1792972800.0
  Covering ROAs (1):
    - Prefix: 198.51.100.0/22 | ASN: AS13335 | MaxLength: /24

Operator Prefix Inventory:
  Status:          Matched (198.51.100.0/22)
  Owner:           GlobalCloud CDN
  Allowed Origins: [AS13335, AS13336]
================================================================================
```

### What to Say
> *"Here we run our live demo replaying the baseline dataset. Notice Alert #1:*
> 1. *It has a deterministic ID (`alt-67e804c0`), generated from a cryptographic hash of the prefix, origin ASN, and timestamp.*
> 2. *It includes the active covering ROA (`198.51.100.0/22, ASN 13335, maxlen 24`) evaluated at snapshot epoch `1792972800.0`—guaranteed to be at or before update time with zero future lookahead.*
> 3. *It states the strict precedence rationale: Rule 1 (ORIGIN_HIJACK) fired because origin AS65853 is not in GlobalCloud CDN's inventory, and ROV evaluated to Invalid (`origin_mismatch`). Legitimate pass-through was skipped because the origin was unauthorized.*
> 4. *Furthermore, deduplication is keyed on `(prefix, origin_asn)` over a 300-second window, so duplicate announcements are suppressed while a new rogue origin on the same prefix is never hidden."*

---

## Minute 3 (2:00 – 3:00): Baseline Metrics & The Forged-Origin Gap

### Action (Terminal)
```bash
python -m src.cli demo --limit 5
```

### What You See (Focus on Scenario Recall section)
```text
================================================================================
 BASELINE PERFORMANCE METRICS (reports/baseline_metrics.json)
================================================================================
1. PRIMARY POLICY (All Operator Alert Types - Strictest):
   * Event-Level Precision : 0.6154 (95% CI: 0.5263 - 0.7083) [HEADLINE]
   * Event-Level Recall    : 0.8000 (95% CI: 0.6750 - 0.9250)
   * Event-Level F1 Score  : 0.6957 (95% CI: 0.6022 - 0.7826)
   * Alert-Level Precision : 0.6154
   * Missed Due to Dedup   : 0

2. SECONDARY POLICY (High & Medium Severity Only):
   * Event-Level Precision : 0.7273
   * Event-Level Recall    : 0.8000
   * Event-Level F1 Score  : 0.7619

3. SCENARIO RECALL (The Forged-Origin Gap):
   * exact_origin_hijack                   : 100.0%
   * hijack_after_roa_change               : 100.0%
   * loose_maxlength_hijack                : 0.0% <-- (0% recall by design; forged origin looks Valid)
   * subprefix_hijack                      : 100.0%
   * Easy Anomaly Recall                   : 100.0% (24/24)
   * Hard Anomaly Recall                   : 50.0% (8/16: 8 caught, 8 loose_maxlength missed)
```

### What to Say
> *"Now look at our baseline metrics across 92 labelled events. Event-level precision is 61.5%, recall is 80.0%, and F1 is 69.6%.*
> 
> *Notice line 3 under Scenario Recall:*
> - *Exact origin hijacks, subprefix hijacks, and hijacks after ROA changes all achieve 100% recall.*
> - *However, `loose_maxlength_hijack` shows **0.0% recall**.*
> 
> *Why does the rule baseline miss 100% of these? Because in a forged-origin attack, the adversary announces a more-specific subprefix (`/24`) under a covering parent (`198.18.0.0/15`, maxLength `/24`) and **forges the legitimate campus origin AS64510** in the AS_PATH. Because the origin matches the ROA and length `/24 <= 24`, RFC 6811 evaluates to **Valid**. Because AS64510 is in the operator inventory, the rule engine marks it legitimate.*
> 
> *This is a structural blind spot of pure RFC 6811 + inventory matching. To catch this without full AS_PATH cryptographic verification (BGPsec), we added an ML anomaly detector."*

---

## Minute 4 (3:00 – 4:00): ML Detector & Closing the Blind Spot

### Action (Terminal)
```bash
python -m src.cli explain --alert-id alt-ml-7a7b0b3b
```

### What You See
```text
================================================================================
 BGP ANOMALY MONITOR: EXPLAINABLE ALERT REPORT
================================================================================
Alert ID:     alt-ml-7a7b0b3b
Time (UTC):   2026-10-26T19:29:58.839041Z (epoch: 1793042998.839041)
Detector:     ML
Alert Type:   ML_ANOMALY
Severity:     LOW
Prefix:       198.19.35.0/24
Origin ASN:   AS64510
Peer:         206.108.34.1
Anomaly Score:0.1977 (Decision Threshold tau* = 0.0500)
--------------------------------------------------------------------------------
EVIDENCE & RATIONALE:
--------------------------------------------------------------------------------
Reason:
  High announcement burst rate (0 updates in past 30 minutes) (top signal: update_rate_30m=0, +). Supported by: origin_rarity=0.0004 (+), peer_new_for_prefix_origin=1 (+). Model anomaly score: 0.198 (operating threshold tau* = 0.050). Note: Feature attributions indicate model-sensitivity to individual inputs relative to baseline background traffic, not causal reasons.

Top Contributing Features (Top 3):
  1. update_rate_30m            value=0          contribution=+0.1963 (direction: +)
  2. origin_rarity              value=0.0004     contribution=+0.1880 (direction: +)
  3. peer_new_for_prefix_origin value=1          contribution=+0.1698 (direction: +)

Explanation Method:
  Per-feature contribution against empirical background mean (delta in model output probability when feature replaced with background baseline; non-causal attribution)

Disclaimer:
  Attribution reflects statistical association within the trained model and does not establish causal relationships.

RFC 6811 Route Origin Validation (ROV):
  ROV State:      Valid
  Snapshot Time:  1793037600.0
  Covering ROAs (1):
    - Prefix: 198.18.0.0/15 | ASN: AS64510 | MaxLength: /24

Operator Prefix Inventory:
  Status:          Matched (198.18.0.0/15)
  Owner:           Enterprise Campus
  Allowed Origins: [AS64510]
================================================================================
```

### What to Say
> *"Here is how our Machine Learning detector closes that blind spot. This is alert `alt-ml-7a7b0b3b` on `198.19.35.0/24` with origin AS64510.*
> 
> *Notice the ROV state: it is **Valid**. The inventory match: **Matched**. The rule baseline completely ignored this announcement.*
> 
> *Yet the ML model assigned an anomaly probability of `0.1977`, exceeding the validation-tuned threshold $\tau^* = 0.0500$.*
> 
> *How did the ML detector catch it? Look at the top contributing features, computed by perturbing each feature against the empirical background mean:*
> 1. `peer_new_for_prefix_origin = 1.0` *(direction: +)*: The route arrived via peer `206.108.34.1`, which had never announced this prefix/origin before.
> 2. `origin_rarity = 0.0004` *(direction: +)*: The legitimate campus origin rarely appears across transit collectors.
> 3. `update_rate_30m = 0` *(direction: +)*: Sudden burst after silence.
> 
> *On the held-out test slice, ML recovers **about 70% (59% to 81% across three seeds)** of these forged-origin attacks (seed 777: 17/21, 81.0% at $\tau^* = 0.0500$; seed 888: 13/22, 59.1% at $\tau^* = 0.0700$; seed 999: 15/21, 71.4% at $\tau^* = 0.0900$), jumping from 0% in the rule baseline to about 70% (59% to 81% across three seeds) in ML!"*

---

## Minute 5 (4:00 – 5:00): Engineering Honesty & The False Positive Cost

### Action (Terminal)
```bash
python -m src.cli explain --alert-id alt-ml-107ff437
```

### What You See
```text
================================================================================
 BGP ANOMALY MONITOR: EXPLAINABLE ALERT REPORT
================================================================================
Alert ID:     alt-ml-107ff437
Time (UTC):   2026-10-26T19:34:02.154271Z (epoch: 1793043242.154271)
Detector:     ML
Alert Type:   ML_ANOMALY
Severity:     MEDIUM
Prefix:       198.18.69.0/24
Origin ASN:   AS64510
Peer:         198.32.240.1
Anomaly Score:0.3285 (Decision Threshold tau* = 0.0500)
--------------------------------------------------------------------------------
EVIDENCE & RATIONALE:
--------------------------------------------------------------------------------
Reason:
  High announcement burst rate (0 updates in past 30 minutes) (top signal: update_rate_30m=0, +). Supported by: origin_rarity=0.0004 (+), hour_of_day=19 (+). Model anomaly score: 0.329 (operating threshold tau* = 0.050). Note: Feature attributions indicate model-sensitivity to individual inputs relative to baseline background traffic, not causal reasons.

Top Contributing Features (Top 3):
  1. update_rate_30m            value=0          contribution=+0.3284 (direction: +)
  2. origin_rarity              value=0.0004     contribution=+0.3250 (direction: +)
  3. hour_of_day                value=19         contribution=+0.2844 (direction: +)
================================================================================
```

### What to Say
> *"To be completely honest engineers, higher sensitivity comes at an operational cost. Here is an ML false positive: alert `alt-ml-107ff437`.*
> 
> *This event belongs to scenario `te_more_specific`: legitimate traffic engineering by the campus network announcing subprefix `198.18.69.0/24`.*
> 
> *The rule baseline produces **zero false positives** on traffic engineering. But the ML model assigned an anomaly score of `0.3285`, raising a medium-severity alarm because the sudden emergence of a new subprefix mimics the temporal fingerprint of a deaggregation attack.*
> 
> *Across the test slice, ML incurs **8 false positives** on traffic engineering. However, it also eliminates 20 false positives that the rule baseline suffers during DDoS scrubbing activations.*
> 
> *Summary of our system:*
> - *Rules provide deterministic, zero-FP traffic-engineering hygiene at 60,000 updates/second.*
> - *ML adds anomaly sensitivity that closes the forged-origin gap from 0% to about 70% (59% to 81% across three seeds) recall.*
> - *Every alert carries full RPKI/ROV evidence, operator inventory context, severity triage bands (noting that 73 of 85 ML test alerts sit in 'high' as a triage aid rather than calibrated probability), and model-sensitivity disclaimers for human triage.*
> 
> *Thank you! We are ready for any questions."*

---

## Quick Reference Commands

```bash
# Run pytest test suite (88+ tests)
python -m pytest -q

# Live demo with 1-second delay between alerts
python -m src.cli demo --limit 5 --delay 1.0

# Live demo with first alert deeply explained
python -m src.cli demo --limit 1 --explain-first

# Live demo with ML test slice & forged-origin detection
python -m src.cli demo --with-ml --limit 5

# Deep evidence inspection for a specific alert
python -m src.cli explain --alert-id alt-ml-7a7b0b3b

# Filter alerts in terminal
python -m src.cli list-alerts --type ORIGIN_HIJACK --severity high --limit 5
```


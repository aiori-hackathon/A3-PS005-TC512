# Detection Loop Pseudocode: Rules & Machine Learning Detectors

This document provides the formal pseudocode for the BGP Anomaly Monitor detection engines, matching the real implementation in [`src/rules.py`](file:///d:/Project/bgp-anomaly-monitor/src/rules.py), [`src/rov.py`](file:///d:/Project/bgp-anomaly-monitor/src/rov.py), and [`src/explain.py`](file:///d:/Project/bgp-anomaly-monitor/src/explain.py).

---

## 1. System Inputs, Data Structures, and State

```text
Type BGPUpdate:
    timestamp  : Float                // Unix epoch seconds
    prefix     : IPNetwork            // IPv4 or IPv6 network
    origin_asn : Integer              // Origin Autonomous System Number
    peer       : String               // Collector transit peering address
    action     : String               // 'announce' or 'withdraw'

Type ROARecord:
    prefix     : IPNetwork
    asn        : Integer
    max_length : Integer

Type ROASnapshot:
    snapshot_time : Float
    records       : RadixTree<ROARecord>

Type InventoryItem:
    prefix               : IPNetwork
    expected_origin_asns : Set<Integer>
    max_expected_length  : Integer
    owner                : String

Type Alert:
    alert_id         : String         // Deterministic SHA-256 derived ID
    time             : Float
    type             : String         // ORIGIN_HIJACK, SUBPREFIX_HIJACK, INVENTORY_MISMATCH, etc.
    prefix           : String
    origin_asn       : Integer
    severity         : String         // 'high', 'medium', 'low'
    detector         : String         // 'rules' or 'ml'
    reason           : String
    evidence         : Dictionary
    suppressed_count : Integer

State Variables:
    roa_store        : TimeOrderedList<ROASnapshot>
    inventory        : RadixTree<InventoryItem>
    dedup_table      : Map<(String, Integer), Alert>    // Key: (prefix_str, origin_asn)
    rolling_history  : SlidingWindowHistory             // Past-only state per prefix and per peer
    ml_model         : GradientBoostingClassifier       // Trained on Train slice (first 60%)
    tau_star         : Float = 0.0500                   // Decision threshold chosen on Validation
    bg_mean          : Vector<Float>                    // Feature-wise empirical mean of background train data
```

---

## 2. Algorithm 1: Time-Aligned RFC 6811 Route Origin Validation (ROV)

```text
Algorithm ValidateRoute(prefix, origin_asn, timestamp, roa_store):
    Input: prefix, origin_asn, timestamp, roa_store
    Output: (state: ROVState, invalid_reason: Optional<String>, snapshot_time: Optional<Float>)

    // 1. Retrieve the latest ROA snapshot at or before the update timestamp
    snapshot <- roa_store.GetSnapshotAtOrBefore(timestamp)
    if snapshot is None then:
        return (state: NoSnapshot, invalid_reason: "no_snapshot_at_or_before_update_time", snapshot_time: None)

    // 2. Find all covering ROAs in the snapshot
    covering_roas <- snapshot.FindCoveringROAs(prefix)
    if covering_roas is empty then:
        return (state: NotFound, invalid_reason: None, snapshot_time: snapshot.snapshot_time)

    // 3. Evaluate RFC 6811 validity criteria
    // A route is Valid if AT LEAST ONE covering ROA matches origin and length <= maxLength
    has_origin_match <- false
    for each roa in covering_roas do:
        if roa.asn == origin_asn then:
            has_origin_match <- true
            if prefix.prefixlen <= roa.max_length then:
                return (state: Valid, invalid_reason: None, snapshot_time: snapshot.snapshot_time)

    // 4. If no valid match, determine specific invalidity reason
    if has_origin_match then:
        return (state: Invalid, invalid_reason: "max_length_exceeded", snapshot_time: snapshot.snapshot_time)
    else:
        return (state: Invalid, invalid_reason: "origin_mismatch", snapshot_time: snapshot.snapshot_time)
```

---

## 3. Algorithm 2: Rule-Based Baseline Anomaly Detector

Strict rule precedence ensures that every announcement produces at most one alert.

```text
Algorithm ProcessUpdateRules(update, inventory, roa_store, dedup_table, dedup_window = 300.0):
    Input: update, inventory, roa_store, dedup_table, dedup_window
    Output: Optional<Alert>

    // 1. Ignore withdrawals: Process announcements only
    if update.action != "announce" then:
        return None

    prefix <- update.prefix
    origin <- update.origin_asn
    ts     <- update.timestamp

    // 2. RFC 6811 RPKI/ROV evaluation (against time-aligned ROA records)
    rov_res <- ValidateRoute(prefix, origin, ts, roa_store)

    // 3. Operator prefix inventory lookups (Exact & Covering)
    inv_exact    <- inventory.LookupExact(prefix)
    inv_covering <- inventory.LookupCovering(prefix)
    inv_item     <- inv_exact if inv_exact is not None else inv_covering
    is_more_spec <- (inv_covering is not None) and (prefix.prefixlen > inv_covering.prefix.prefixlen)
    origin_in_inv <- inventory.IsOriginAllowed(prefix, origin)

    // --- Rule Evaluation: Legitimate Pass-Through (NO ALERT) ---
    // A. Authorized operator route with ROV Valid
    if origin_in_inv and rov_res.state == Valid then:
        return None

    // B. Benign unmonitored Internet route with Valid or NotFound ROV state
    if inv_item is None and (rov_res.state == Valid or rov_res.state == NotFound) then:
        return None

    candidate_alert <- None

    // --- Strict Rule Precedence Table ---

    // Precedence 1: ORIGIN_HIJACK (Exact match on inventory prefix by unauthorized origin)
    if inv_exact is not None and (not origin_in_inv) and (rov_res.state != Valid) then:
        if rov_res.state == NoSnapshot then:
            severity <- "low"
            reason   <- "ROV could not be evaluated: no ROA snapshot at or before this time"
        else:
            severity <- "high"
            reason   <- "Unauthorized origin AS" + origin + " announced exact inventory prefix"
        candidate_alert <- CreateAlert(ts, "ORIGIN_HIJACK", prefix, origin, severity, rov_res, inv_exact, reason)

    // Precedence 2: SUBPREFIX_HIJACK (More-specific of inventory prefix by unauthorized origin)
    else if is_more_spec and (not origin_in_inv) and (rov_res.state != Valid) then:
        if rov_res.state == NoSnapshot then:
            severity <- "low"
            reason   <- "ROV could not be evaluated: no ROA snapshot at or before this time"
        else:
            severity <- "high"
            reason   <- "Subprefix /" + prefix.prefixlen + " hijacked by unauthorized AS" + origin
        candidate_alert <- CreateAlert(ts, "SUBPREFIX_HIJACK", prefix, origin, severity, rov_res, inv_covering, reason)

    // Precedence 3: INVENTORY_MISMATCH (ROV Valid per RPKI but missing from operator inventory documentation)
    else if inv_item is not None and (not origin_in_inv) and (rov_res.state == Valid) then:
        severity <- "low"
        reason   <- "ROV Valid per RPKI ROA but origin AS" + origin + " not registered in operator inventory"
        candidate_alert <- CreateAlert(ts, "INVENTORY_MISMATCH", prefix, origin, severity, rov_res, inv_item, reason)

    // Precedence 4: ROA_INVALID (RFC 6811 Invalid on operator inventory prefix)
    else if inv_item is not None and (rov_res.state == Invalid) then:
        if origin_in_inv then:
            severity <- "medium"
            reason   <- "Origin authorized in operator inventory but ROA state is Invalid (ROA update lag)"
        else:
            severity <- "high"
            reason   <- "RFC 6811 Invalid on operator prefix: " + rov_res.invalid_reason
        candidate_alert <- CreateAlert(ts, "ROA_INVALID", prefix, origin, severity, rov_res, inv_item, reason)

    // Precedence 5: THIRD_PARTY_INVALID (RFC 6811 Invalid on unmonitored external routes)
    else if inv_item is None and (rov_res.state == Invalid) then:
        severity <- "low"
        reason   <- "Third-party Internet route outside operator inventory is RFC 6811 Invalid (" + rov_res.invalid_reason + ")"
        candidate_alert <- CreateAlert(ts, "THIRD_PARTY_INVALID", prefix, origin, severity, rov_res, None, reason)

    // Precedence 6: ROA_MISSING (Authorized operator prefix without ROA protection)
    else if inv_item is not None and (rov_res.state == NotFound) then:
        severity <- "low"
        reason   <- "Operator inventory prefix announced without RPKI ROA protection (NotFound)"
        candidate_alert <- CreateAlert(ts, "ROA_MISSING", prefix, origin, severity, rov_res, inv_item, reason)

    if candidate_alert is None then:
        return None

    // --- Deduplication Engine ---
    // Deduplication key is strictly (prefix_str, origin_asn)
    // A NEW origin on the same prefix has a different key and is NEVER suppressed!
    dedup_key <- (String(prefix), origin)
    if dedup_key in dedup_table then:
        existing <- dedup_table[dedup_key]
        if (ts - existing.time) <= dedup_window then:
            existing.suppressed_count <- existing.suppressed_count + 1
            return None // Suppressed within 300s window

    dedup_table[dedup_key] <- candidate_alert
    return candidate_alert
```

---

## 4. Algorithm 3: Machine Learning Detector & Feature Attribution

```text
Algorithm ProcessUpdateML(update, rolling_history, ml_model, tau_star, bg_mean, dedup_table, dedup_window = 300.0):
    Input: update, rolling_history, ml_model, tau_star, bg_mean, dedup_table, dedup_window
    Output: Optional<Alert>

    if update.action != "announce" then:
        return None

    prefix <- update.prefix
    origin <- update.origin_asn
    ts     <- update.timestamp
    peer   <- update.peer

    // 1. Extract 10 past-only features (zero future lookahead)
    // Features include: rov_state_encoded, origin_in_inventory, prefix_len_delta,
    // origin_new_for_prefix, peer_new_for_prefix_origin, more_specific_first_seen,
    // prefix_age_hours, origin_rarity, update_rate_30m, hour_of_day.
    feature_vector x <- rolling_history.ExtractPastFeatures(update)
    rolling_history.Update(update) // Record state for future updates

    // 2. Predict anomaly probability using trained GradientBoosting model
    p_anomaly <- ml_model.PredictProba(x)[Class_1]

    // 3. Evaluate decision boundary
    if p_anomaly < tau_star then:
        return None // Normal / sub-threshold

    // 4. Deduplication Check
    dedup_key <- ("ml", String(prefix), origin)
    if dedup_key in dedup_table then:
        existing <- dedup_table[dedup_key]
        if (ts - existing.time) <= dedup_window then:
            existing.suppressed_count <- existing.suppressed_count + 1
            return None

    // 5. Map continuous score to operational severity band (triage aid, not calibrated probability)
    // Note: Due to steep GBDT decision margins, 73 of 85 test slice ML alerts evaluate to 'high'.
    if p_anomaly >= 0.70 then:
        severity <- "high"
    else if p_anomaly >= 0.30 then:
        severity <- "medium"
    else:
        severity <- "low"

    // 6. Compute Feature Attribution (Marginal Permutation vs Background Mean)
    // Delta_i = P(y=1 | x) - P(y=1 | x_{-i}, mean_i)
    contributions <- List()
    for each feature f_i in Features do:
        x_perturbed <- Copy(x)
        x_perturbed[f_i] <- bg_mean[f_i]
        p_perturbed <- ml_model.PredictProba(x_perturbed)[Class_1]
        delta_i <- p_anomaly - p_perturbed
        direction <- "+" if delta_i > 0.0001 else ("-" if delta_i < -0.0001 else "0")
        contributions.Append((feature: f_i, value: x[f_i], delta: delta_i, direction: direction))

    Sort contributions descending by delta_i
    top3 <- contributions[0..2]

    // 7. Generate Plain-English Reason Text
    lead_description <- DescribeFeatureSignal(top3[0].feature, top3[0].value)
    reason <- FormatMLReason(lead_description, top3, p_anomaly, tau_star)

    alert <- CreateMLAlert(
        alert_id=MakeDeterministicID("ml", prefix, origin, ts),
        time=ts,
        type="ML_ANOMALY",
        prefix=prefix,
        origin=origin,
        severity=severity,
        score=p_anomaly,
        threshold=tau_star,
        top_features=top3,
        reason=reason
    )

    dedup_table[dedup_key] <- alert
    return alert
```

---

## 5. Architectural Complexity and Latency Profile

| Dimension | Rule-Based Baseline | Machine Learning Detector |
|---|---|---|
| **Lookup Data Structure** | Radix / Trie tree exact + LPM | Tabular rolling state + 100 Decision Trees |
| **Time Complexity** | $O(L)$ where $L \le 128$ bits (IPv6) | $O(K \times \text{depth})$ where $K = 100, \text{depth} = 4$ |
| **Memory Consumption** | $O(N)$ prefixes + snapshots ($\approx 10\text{ MB}$) | $O(N)$ sliding windows + tree parameters ($\approx 45\text{ MB}$) |
| **Wall-Clock Processing Speed** | **0.0153 ms / update** (>65,000 updates/sec) | **0.60 ms / update** (~1,600 updates/sec) |
| **Validation Assurance** | Strict RFC 6811 ROV against ROA records | Statistical anomaly estimation |
| **Forged-Origin Recall** | **0.0%** (by design; origin in ROA) | **about 70% (59% to 81% across three seeds)** (recovers from transit metadata; seed 777: 81.0% at $\tau^* = 0.050$, seed 888: 59.1% at $\tau^* = 0.070$, seed 999: 71.4% at $\tau^* = 0.090$) |
| **DDoS Scrubbing Handling** | 100% false alarms on unregistered origin | 0% false alarms (adapts to multi-origin patterns) |
| **Traffic Engineering Handling** | **0% false alarms** (zero FP on valid routes) | 8 false alarms on newly emerged subprefixes |


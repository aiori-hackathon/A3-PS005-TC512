"""Unit tests for Phase 8: Streamlit Read-Only Dashboard (app/dashboard.py).

Verifies:
  1. Pure data-loading functions load real files correctly without needing a browser.
  2. Missing or invalid file paths are handled gracefully (return None / [] instead of crashing).
  3. Dynamic extraction of headline metrics matches verified benchmark values.
  4. The forged-origin spotlight alert exists and links to ground-truth labels.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from app.dashboard import (
    load_csv_file,
    load_json_file,
    load_jsonl_file,
    load_text_file,
)


def test_load_json_file_success() -> None:
    """Verify loading existing JSON files returns valid dicts."""
    bm = load_json_file("reports/baseline_metrics.json")
    assert bm is not None
    assert "primary_policy_all_alerts" in bm
    assert bm["primary_policy_all_alerts"]["event_metrics"]["f1"] == 0.6957

    mm = load_json_file("reports/ml_metrics.json")
    assert mm is not None
    assert "multi_seed_aggregated_results" in mm
    assert mm["multi_seed_aggregated_results"]["ML Alone"]["f1_mean"] == 0.9104


def test_load_json_file_missing_path() -> None:
    """Verify missing JSON path returns None gracefully."""
    res = load_json_file("reports/nonexistent_file_xyz.json")
    assert res is None


def test_load_jsonl_file_success() -> None:
    """Verify loading JSONL files returns non-empty list of alert records."""
    alerts = load_jsonl_file("reports/alerts.jsonl")
    assert len(alerts) > 0
    assert any(a.get("alert_id") == "alt-ml-7a7b0b3b" for a in alerts)

    base_alerts = load_jsonl_file("reports/baseline_alerts.jsonl")
    assert len(base_alerts) > 0


def test_load_jsonl_file_missing_path() -> None:
    """Verify missing JSONL path returns empty list gracefully."""
    res = load_jsonl_file("reports/nonexistent_file_xyz.jsonl")
    assert res == []


def test_load_csv_file_success() -> None:
    """Verify loading CSV files returns pandas DataFrame with expected row counts."""
    labels = load_csv_file("data/labels.csv")
    assert labels is not None
    assert len(labels) == 92
    assert "scenario" in labels.columns

    ml_labels = load_csv_file("data/ml_labels.csv")
    assert ml_labels is not None
    assert len(ml_labels) == 1020


def test_load_csv_file_missing_path() -> None:
    """Verify missing CSV path returns None gracefully."""
    res = load_csv_file("data/nonexistent_file_xyz.csv")
    assert res is None


def test_load_text_file() -> None:
    """Verify text loader returns file contents or None."""
    txt = load_text_file("requirements-dashboard.txt")
    assert txt is not None
    assert "streamlit" in txt

    missing = load_text_file("nonexistent_text_xyz.txt")
    assert missing is None


def test_forged_origin_spotlight_alert_present() -> None:
    """Verify target alert alt-ml-7a7b0b3b is present with valid evidence and ground truth."""
    alerts = load_jsonl_file("reports/alerts.jsonl")
    target = next((a for a in alerts if a.get("alert_id") == "alt-ml-7a7b0b3b"), None)
    assert target is not None
    assert target["prefix"] == "198.19.35.0/24"
    assert target["origin_asn"] == 64510
    assert target["type"] == "ML_ANOMALY"

    ev = target.get("evidence", {})
    assert ev.get("rfc6811_state") == "Valid"
    assert "top_contributing_features" in ev

    # Check ground truth label
    ml_labels = load_csv_file("data/ml_labels.csv")
    assert ml_labels is not None
    match = ml_labels[(ml_labels["prefix"] == "198.19.35.0/24") & (ml_labels["origin_asn"] == 64510)]
    assert not match.empty
    assert match.iloc[0]["scenario"] == "loose_maxlength_hijack"
    assert not bool(match.iloc[0]["benign"])


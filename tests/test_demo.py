"""Tests for Phase 7: Demo CLI Command (python -m src.cli demo).

Verifies:
  1. Exit code 0 for baseline demo replay and presence of expected headings.
  2. Explain-first option pretty-prints complete evidence for alert #1.
  3. With-ML option replays test slice, displays head-to-head comparison, and highlights forged-origin catch.
  4. Demo execution is strictly read-only and modifies zero files in reports/ and data/.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


def _hash_file(p: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _snapshot_directory_state(directories: list[Path]) -> dict[Path, str]:
    """Capture a snapshot mapping each file path to its SHA-256 hash."""
    state: dict[Path, str] = {}
    for d in directories:
        if d.exists():
            for p in d.rglob("*"):
                if p.is_file():
                    state[p] = _hash_file(p)
    return state


def test_demo_baseline_runs_exit_code_zero() -> None:
    """Verify demo command runs offline, exits 0, and prints expected baseline sections."""
    res = subprocess.run(
        [sys.executable, "-m", "src.cli", "demo", "--limit", "3"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"demo failed with error:\n{res.stderr}"

    stdout = res.stdout
    # Verify banner and setup
    assert "BGP ORIGIN & SUBPREFIX ANOMALY MONITOR: LIVE DEMONSTRATION" in stdout
    assert "data/feed_replay.csv" in stdout
    assert "RuleBasedDetector" in stdout

    # Verify live alert lines
    assert "ALERT alt-" in stdout
    assert "stopped baseline replay after 3 alerts" in stdout

    # Verify baseline metrics headings
    assert "BASELINE PERFORMANCE METRICS (reports/baseline_metrics.json)" in stdout
    assert "1. PRIMARY POLICY" in stdout
    assert "Event-Level Precision" in stdout
    assert "Event-Level Recall" in stdout
    assert "Event-Level F1 Score" in stdout
    assert "2. SECONDARY POLICY" in stdout
    assert "3. SCENARIO RECALL (The Forged-Origin Gap)" in stdout
    assert "loose_maxlength_hijack" in stdout
    assert "0.0%" in stdout
    assert "4. BENIGN SCENARIO FALSE POSITIVES" in stdout


def test_demo_explain_first_prints_evidence() -> None:
    """Verify --explain-first pretty-prints full cryptographic and inventory evidence for alert #1."""
    res = subprocess.run(
        [sys.executable, "-m", "src.cli", "demo", "--limit", "1", "--explain-first"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"demo --explain-first failed:\n{res.stderr}"

    stdout = res.stdout
    assert "[ALERT #1 - EXPLAIN-FIRST EVIDENCE REPORT]" in stdout
    assert "BGP ANOMALY MONITOR: EXPLAINABLE ALERT REPORT" in stdout
    assert "EVIDENCE & RATIONALE:" in stdout
    assert "RFC 6811 Route Origin Validation (ROV):" in stdout
    assert "Operator Prefix Inventory:" in stdout
    assert "Covering ROAs" in stdout
    assert "stopped baseline replay after 1 alerts" in stdout


def test_demo_with_ml_highlights_forged_origin() -> None:
    """Verify --with-ml replays ML test slice and highlights the forged-origin catch."""
    res = subprocess.run(
        [sys.executable, "-m", "src.cli", "demo", "--with-ml", "--limit", "5"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"demo --with-ml failed:\n{res.stderr}"

    stdout = res.stdout
    # Verify ML test slice section
    assert "MACHINE LEARNING DETECTOR: TEST SLICE REPLAY" in stdout
    assert "data/ml_feed_replay.csv" in stdout
    assert "Operating Boundary: Threshold tau* = 0.0500" in stdout

    # Verify forged-origin callout
    assert ">>> [FORGED-ORIGIN CATCH (RULES MISSED)]" in stdout
    assert "[TP: loose_maxlength_hijack]" in stdout
    assert "alt-ml-7a7b0b3b" in stdout
    assert "198.19.35.0/24" in stdout
    assert "AS64510" in stdout
    assert "Rules blind to forged origins: 0.0% recall" in stdout
    assert "tau* 0.0500" in stdout

    # Verify head-to-head comparison table
    assert "HEAD-TO-HEAD COMPARISON ON HELD-OUT TEST SLICE (reports/ml_metrics.json)" in stdout
    assert "Seed 777: Rules" in stdout
    assert "3-Seed: Rules" in stdout
    assert "Seed 777: ML" in stdout
    assert "Forged-Origin Recall" in stdout
    assert "80.95%" in stdout
    assert "about 70% (59% to 81% across three seeds)" in stdout
    assert "21 events fall in the row-based test slice; evt-0399 starts 17 s before the boundary and counts in validation." in stdout
    assert "Scrubbing False Positives" in stdout
    assert "Traffic Engineering FPs" in stdout


def test_demo_command_modifies_no_files() -> None:
    """Verify demo execution is strictly read-only and alters no files in data/ or reports/."""
    watched_dirs = [Path("data"), Path("reports")]
    state_before = _snapshot_directory_state(watched_dirs)

    # Run demo with all options enabled
    res = subprocess.run(
        [sys.executable, "-m", "src.cli", "demo", "--with-ml", "--limit", "3", "--explain-first"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0

    state_after = _snapshot_directory_state(watched_dirs)

    # Ensure no files added or removed
    assert set(state_before.keys()) == set(state_after.keys()), "File list in data/ or reports/ changed during demo"

    # Ensure all file hashes are bitwise identical
    for path, hash_val in state_before.items():
        assert state_after[path] == hash_val, f"File '{path}' was modified during demo run!"


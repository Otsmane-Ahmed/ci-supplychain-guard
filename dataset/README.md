# Research Dataset & Ground Truth

This directory acts as the Evidence Locker for the research. It contains the complete corpus of malicious, benign, and simulated software packages used to evaluate the CI-Guard system.

## Directory Structure

### 1. `private_raw/` (GitIgnored)
**Status:** DANGER ZONE
**Content:** Live, un-sanitized malware samples. This directory is strictly excluded from version control to prevent accidental proliferation.
* **`datadog_malware/`**: The full clone of the Datadog Malicious Software Packages dataset (password-protected zips).
* **`real_malware_extracted/`**: The "Active Testing Ground." Contains the 20 specific samples extracted and used for the final benchmark (e.g., `fulfillment-portal-common`).
* **`simulated_shai_hulud/`**: Custom-written malware simulating the "Shai-Hulud" worm logic (tests exfiltration behaviors).
* **`test_false_positive/`**: JavaScript files containing commented-out malicious patterns (tests the "Dead Code" logic).
* **`malicious_flatmap_stream/`**: A reconstruction of the infamous 2018 Event-Stream attack.

### 2. `sanitized_samples/`
**Status:** SAFE
**Content:** Harmless code used for performance baselining and false positive testing.
* **`benign_lodash/`**: A known-good copy of the popular `lodash` library. Used to measure the "Scan Time Overhead" (0.34s) added by our tool.

## Files

### `schema.csv`
**Type:** Metadata Index
**Function:** The central registry of all samples. It tracks:
* **ID:** Unique identifier (e.g., `sim-001`).
* **Source:** Origin (NPM, PyPI, Simulator).
* **Label:** `malicious`, `benign`, or `simulated`.
* **Evidence:** Which specific pattern (e.g., `process.env`) flagged the file.

### `INTAKE_CHECKLIST.md`
**Type:** Safety Protocol
**Function:** A strict checklist that must be followed before downloading any new malware.
* **Key Rules:** Use isolated VMs, verify network air-gaps, and never execute outside the sandbox.

## Usage in Research
This dataset is partitioned into three test groups for the IEEE paper:
1.  **Attack Group:** `real_malware_extracted/` + `simulated_shai_hulud/` (Measuring True Positive Rate).
2.  **Control Group:** `benign_lodash/` (Measuring Runtime Overhead).
3.  **Stress Group:** `test_false_positive/` (Measuring False Positive Rate).

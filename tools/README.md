# Research & Forensic Tools

This directory contains utility scripts designed to support the experimental phase of the CI-Guard research. These tools handle dataset preparation, malware extraction, and forensic analysis of detection failures. They are not required for the standard operation of the guard pipeline.

## Files

### 1. `unpack_real_malware.py`
**Type:** Dataset Preparation Utility
**Function:**
* Interacts with the cloned Datadog Malicious Software Packages repository.
* Recursively scans for password-protected malware artifacts (ZIPs).
* Randomly selects and extracts a specified number of samples (default: 20) using the standard quarantine password (`infected`).
* Populates the `dataset/private_raw/real_malware_extracted/` directory for active testing.

### 2. `explain_failures.py`
**Type:** Forensic Analysis Engine
**Function:**
* Automates the "Failure Analysis" phase of the research.
* Iterates through the extracted malware samples and executes the full CI-Guard pipeline against them.
* If a known malicious sample receives a `SAFE` or `WARNING` verdict (False Negative), the script initiates a secondary forensic scan.
* Searches the source code for specific high-risk keywords (e.g., `discord`, `ipinfo`, `eval`) that may have been missed by the primary regex engine due to proximity limitations.
* Outputs evidence used to identify evasion techniques (e.g., "Stalling" or "Decoupled Exfiltration").

## Usage

These scripts are intended to be run manually by the researcher during the evaluation phase.

```bash
# Step 1: Prepare the test ground
python3 tools/unpack_real_malware.py

# Step 2: Analyze why certain samples bypassed detection
python3 tools/explain_failures.py
```

# Evaluation Plan: CI Supply Chain Guard

## 1. Research Questions
* **RQ1:** How effective are static heuristics at detecting known patterns of malicious CI modifications compared to obfuscated attacks?
* **RQ2:** To what extent can lightweight dynamic sandboxing (Active Deception) identify evasion techniques that bypass static analysis?
* **RQ3:** What is the trade-off between detection capability and developer friction (runtime overhead, false positives) in a hardened CI pipeline?

## 2. Evaluation Datasets
We utilize a 70/15/15 split for training (rule tuning), validation, and testing.

| Dataset Source | Type | Size (Est.) | Purpose |
| :--- | :--- | :--- | :--- |
| **Simulated Samples** | Malicious | 150 | Generated samples (e.g., `simulated_shai_hulud`) testing specific TTPs. |
| **Benign Controls** | Safe | 800 | Popular NPM packages (e.g., `lodash`, `express`) to test False Positives. |
| **Backstabber / OSPtrack** | Ground Truth | 30+ | **** Real-world historical attacks for validation (e.g., `event-stream`). |

## 3. Experiment Types
1.  **Static-Only Detection:** Measure detection rate using only Regex+AST (No Sandbox).
2.  **Hybrid Detection (Static + Sandbox):** Measure improvement in TPR when Sandbox is enabled.
3.  **Obfuscation Resistance:** Test against Base64 and AES-encrypted payloads.
4.  **Ecosystem Comparison:** Contrast detection rates between NPM (JS) and PyPI (Python).
5.  **CI Runtime Cost:** Measure average increase in build time (Target: <30s overhead).
6.  **Developer Friction:** Measure False Positive Rate on Benign PRs.

## 4. Metrics
* **True Positive Rate (TPR):** (Detected Malware / Total Malware) * 100
* **False Positive Rate (FPR):** (Blocked Safe / Total Safe) * 100
* **Precision & Recall:** Standard ML metrics.
* **F1 Score:** Harmonic mean of Precision and Recall.
* **Detection Improvement:** % increase in detection from Reachability Analysis and Masquerading.
* **Detection Rate on OSPtrack:** Target > 90% (Real-world validation).

# Research Paper Outline

## Abstract
Summary of the problem (CI attacks), the gap (static scanners fail), and the solution (Hybrid Guard with Deception).

## 1. Introduction
* **Problem:** CI/CD pipelines are the new attack surface.
* **Motivation:** Maintainers need lightweight, unprivileged tools to block attacks before merging.

## 2. Related Work
* Comparison with Snyk, Dependabot, and CodeQL.
* Analysis of "Backstabber's Knife Collection" and recent attacks.

## 3. Threat Model
* **Attacker Capabilities:** Can modify PR code, obfuscate payloads, check for CI env vars.
* **Defender Capabilities:** CI checks, no root access, limited runtime.

## 4. Methodology (The Core Contribution)
* **System Design:** The "Traffic Light" Protocol.
* **Static Analysis:**
    * **(Reachability):** AST-based filtering of dead code to reduce False Positives.
* **Dynamic Sandbox:**
    * **(Isolation):** User-space isolation (Proot/Sysbox) for GitHub Actions compatibility.
    * **(Active Deception):** Masquerading as a developer laptop (Honeytokens, Fake History).
* **CI Integration:** Automated decision engine (`main_guard.py`).

## 5. Dataset
* Breakdown of MalOSS, OSPtrack, and simulated samples.

## 6. Evaluation & Results
* **RQ1 Results:** Static analysis performance.
* **RQ2 Results:** Sandbox effectiveness against "sleeping" malware.
* **RQ3 Results:** Runtime performance graphs.

## 7. Discussion
* Why Deception works better than simple scanning.
* Limitations (e.g., Time-based evasion).

## 8. Conclusion
* Summary of contributions and future work.

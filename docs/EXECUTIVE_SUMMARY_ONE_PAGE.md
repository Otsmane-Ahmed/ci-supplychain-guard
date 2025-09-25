# Executive Summary: CI Supply Chain Guard

## 1. Purpose
Software supply chain attacks have increased by 742% (Sonatype). Traditional scanners rely on known signatures, failing to detect novel "Zero-Day" attacks in Pull Requests. This project develops **CI-Guard**, a hybrid defense system designed to block malicious code *before* it merges.

## 2. Novelty & Innovation
Unlike standard scanners, this research introduces three key innovations:
1.  **Active Deception:** A sandbox that "lies" to malware, mimicking a developer's laptop with fake user history and Honeytokens to bypass anti-CI checks.
2.  **Reachability Analysis:** An AST-based filter that distinguishes between executable malware and harmless comments, significantly reducing developer friction.
3.  **Unprivileged Execution:** Designed using **Proot/Sysbox** to run securely inside restricted CI environments like GitHub Actions.

## 3. Dataset Size
* **Total Samples:** ~1,000
* **Malicious:** 150+ (Simulated TTPs) + 30 (Historical Ground Truth via OSPtrack/Backstabber).
* **Benign:** 800+ (Top NPM packages).

## 4. Key Results
* **Detection Rate:** Achieved **100% TPR** against simulated exfiltration attacks using the Deception Sandbox.
* **False Positive Reduction:** Reachability analysis reduced false flags on non-executable code (Score 10 -> 5).
* **Performance:** Average scan time < 45 seconds per package.

## 5. Impact
This tool provides Open Source maintainers with a **free, automated, and high-accuracy** defense layer. It prevents account takeovers (via token theft) and reduces the risk of malicious dependencies polluting the ecosystem.

## 6. Research Excellence
This project demonstrates rigorous engineering by combining **Static Analysis** (AST parsing), **System Security** (Container isolation), and **Behavioral Analysis** (Syscall tracing). It addresses the "Works on My Machine" problem by ensuring compatibility with standard CI runners.

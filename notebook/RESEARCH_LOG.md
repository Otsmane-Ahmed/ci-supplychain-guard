# Research Lab Notebook: CI-SupplyChain-Guard

**Project Status:** Phase 7 (Evaluation & Documentation)
**Principal Investigator:** Otsmane Ahmed

---

## 1. Introduction

### Problem Statement
1.  **The Escalating Threat:** Supply-chain attacks have shifted left, targeting the Continuous Integration (CI) pipeline itself (e.g., *tj-actions*, *Codecov*); however, developers inherently trust build commands like `npm install` to run safely within their privileged infrastructure, creating a massive blind spot.
2.  **The Detection Gap:** Current defenses are either reactive (scanning published artifacts *after* a compromise has occurred) or too resource-intensive for the "Pre-Merge" phase (e.g., full heavy sandboxing like Cuckoo), failing to detect malicious lifecycle scripts before they exfiltrate secrets.
3.  **The Need for Lightweight Defense:** Open-source maintainers currently lack a low-friction, automated tool that can detect malicious intent in Pull Requests (such as environment variable exfiltration or obfuscation) without significantly slowing down the development workflow or requiring complex infrastructure.

### Research Questions (RQs)
* **RQ1: Static Analysis Effectiveness**
    * *Question:* How effective are static heuristics (regex, AST analysis) at detecting known patterns of malicious CI modifications compared to obfuscated attacks?
    * *Hypothesis:* We hypothesize that static analysis will achieve high recall (>90%) on simple "low-hanging fruit" attacks but will fail significantly (<40% recall) against obfuscated payloads.
* **RQ2: Dynamic Sandboxing Value**
    * *Question:* To what extent can lightweight dynamic sandboxing identify evasion techniques (e.g., obfuscation, external fetches) that bypass static analysis?
    * *Hypothesis:* We expect that a short-duration sandbox (running for <30 seconds) will detect 100% of network-based exfiltration attempts that static analysis misses, specifically catching "curl-pipe-bash" attacks and DNS exfiltration.
* **RQ3: Operational Trade-offs**
    * *Question:* What is the trade-off between detection capability and developer friction (runtime overhead, false positives) in a hardened CI pipeline?
    * *Hypothesis:* We propose that a "Funnel Architecture" (static first, dynamic second) can keep the average CI overhead under 30 seconds while maintaining a false positive rate below 5%.

---

## 2. Threat Model

### Attacker Goals (Objectives)
Based on analyzed incidents (e.g., Shai-Hulud, warbeast2000), the adversary aims to:
1.  **Exfiltrate Secrets:** Steal CI environment variables (GITHUB_TOKEN, NPM_TOKEN, AWS_ACCESS_KEY_ID) to pivot into cloud infrastructure.
2.  **Poison Build Artifacts:** Inject malicious code into the published package (e.g., dist/index.js) to compromise downstream users.
3.  **Establish Persistence:** Modify repository files (e.g., adding a malicious GitHub Action workflow) to maintain access after the PR is closed.

### Attacker Capabilities
1.  **Malicious Contributor (The "PR Attacker"):** Can fork the repository and submit Pull Requests. Can modify source code, config files (package.json), and build scripts. *Constraint:* Cannot directly modify protected branches or Repository Secrets without a merged PR.
2.  **Compromised Maintainer (The "Account Takeover"):** Has write access to the repository and package registry. Can push directly to main.

### Defender Assumptions
1.  **Ephemeral Runner:** The CI environment is clean at the start of the job.
2.  **Pre-Install Scan:** The defense tool executes *before* the installation of untrusted dependencies.
3.  **Network Visibility:** The defense mechanism can monitor network traffic within the container.

### Out of Scope
* **Endpoint Compromise:** Malware executing on the developer's local laptop.
* **Zero-Day Kernel Exploits:** Container escapes via kernel vulnerabilities.
* **Social Engineering:** Phishing attacks requiring manual approval.

---

## 3. Evidence Log & Taxonomy

### Taxonomy Refinement (Antigravity Update)
To ensure academic rigor, analysis distinguishes between **Technique (TTP)** and **Objective (Impact)**.
* **Technique:** The code pattern (e.g., `process.env` access, `dns.lookup`, `fs.read(~/.ssh)`).
* **Objective:** The goal (e.g., Credential Harvesting, Lateral Movement).

### Incident Catalog
| Incident Name | Ecosystem | Attack Vector | Technique (TTP) | Objective |
| :--- | :--- | :--- | :--- | :--- |
| **Shai-Hulud Worm (2025)** | npm | Maintainer Compromise | `postinstall` script injection | Secret Exfiltration (Worming) |
| **warbeast2000** | npm | Typosquatting | `postinstall` fetching remote 2nd stage | SSH Key Theft |
| **event-stream (2018)** | npm | Social Engineering | AES-encrypted payload in dependency | Wallet Credential Theft |
| **electron-native-notify** | npm | Typosquatting | HTTPS exfiltration of `process.env` | Credential Harvesting |
| **Zapier AI Actions** | npm | Supply Chain | Preinstall script execution | Credential Harvesting |

---

## 4. Dataset Design

### Labeling Rules
* **Malicious:** Confirmed by a security advisory (GitHub/npm/PyPI) or observed malicious behavior in sandbox.
* **Benign:** No signs of malicious behavior; the repository is healthy and widely trusted.
* **Simulated:** Ethically crafted example created to test specific detection capabilities.

### Sampling Strategy (The "Long Tail" Fix)
To avoid selection bias and ensure a realistic False Positive Rate (FPR), the **800 Benign Samples** are stratified as follows:
1.  **Standard (400):** Top-starred repos (e.g., React, Express). Represents "Clean" code.
2.  **Dev Tooling (200):** Linters, CLIs, Scaffolders. *Rationale:* These legitimately use "suspicious" features like file system access and shell execution.
3.  **Niche/Messy (200):** Low-star (<500) but maintained packages. *Rationale:* Amateur code often uses poor practices (e.g., `eval`) that trigger false positives.

### Storage & Sanitization Policy
* **Raw Malware:** Stored in `dataset/private_raw/`. **NEVER COMMIT TO GIT.**
* **Sanitization Rule (Payload vs. Structure):** When creating public samples for `dataset/sanitized_samples/`, we preserve the *structure* of the attack but neutralize the *payload*.
    * *Bad:* Removing `eval(base64(...))` entirely.
    * *Good:* Changing `eval(base64("malicious"))` to `eval(base64("console.log('safe')"))`. This preserves the detection signal.

---

## 5. Experimental Results (Summary)

### Benchmark Data (Phase 7)
| Dataset | N | Detection Rate (TPR) | False Positive Rate (FPR) | Avg Time |
| :--- | :--- | :--- | :--- | :--- |
| **Benign Control** | 50 | N/A | **0%** | 0.34s |
| **Simulated Malware** | 50 | **100%** | N/A | 0.05s |
| **Wild Malware (Datadog)** | 20 | **40%** | N/A | 0.09s |

### Failure Analysis (True Negatives)
Forensic analysis of the 12 missed wild samples identified two primary evasion vectors:
1.  **Discord Webhook Exfiltration:** Decoupling of data collection and transmission sources bypassed static proximity rules.
2.  **Sandbox Stalling:** Malware attempted benign network checks (e.g., `ipinfo.io`) before execution. The strict air-gapped sandbox caused these checks to fail, terminating the malware early.

---

## 6. Ethics Notes
* **Vulnerability Handling:** Vulnerabilities discovered in live packages are reported via official security channels (90-day disclosure).
* **Safety:** All live malware is handled in isolated VMs/containers with network egress disabled.
* **Attribution:** No attribution of threat actors is made without corroborating threat intelligence.

# Antigravity Updates: Critical Refinements for Phases 1 & 2

These updates address specific academic critiques to elevate the research from a standard master's project to a publishable contribution. Apply these guidelines during the execution of Phases 3 (Data Collection) and 4 (Static Analyzer Design).

## 1. Refining the Taxonomy (Phase 1 Fixes)

**Critique:** Overlap between "Incidents" (what happened), "Techniques" (how it happened), and "Objectives" (why it happened). "Token Theft" is an objective, "Env Var Access" is the technique.
**Action:** In your final paper/thesis, strictly follow the *Action-Objective* model.

### Instruction A: Retag "Token Theft" vs "Env Var Access"
When analyzing samples in Phase 3, record data in two separate columns:
*   **Technique (TTP):** What code pattern is present?
    *   *Examples:* `process.env` read, file read (`~/.ssh`), exfiltration via `DNS` or `HTTPS`.
*   **Objective (Impact):** What is the goal?
    *   *Examples:* Credential Harvesting, Resource Hijacking, lateral movement.

### Instruction B: Explicitly Include "Build-Time Tampering"
Expand your definition of "Lifecycle Scripts" to include build-tooling beyond `npm`.
*   **Add to Search/Collection Scope:**
    *   `Makefile` (hooks like `all:`, `install:`)
    *   `build.rs` (Rust remote execution)
    *   `setup.py` / `__init__.py` (Python execution on plain install)
    *   `configure` scripts
*   **Why:** This proves your tool is "Ecosystem Agnostic" at the design level, even if the prototype only supports JS/Python.

## 2. Improving Dataset Validity (Phase 2 Fixes)

**Critique:** "Selection Bias" in benign samples. Scanning only the Top 500 popular packages will result in an artificially low False Positive Rate (FPR) because popular code is "clean" and standardized. Your tool will look great in the lab but fail in the real world.
**Action:** Intentionally pollute the benign dataset with "messy" code.

### Instruction C: The "Long Tail" Sampling Strategy
When executing **Step 3.4 (Collect Benign Samples)**, do NOT just pick the top 1000 repos. Use this split for the 800 benign samples:
*   **400 "Standard" Samples:** Top starred repos (clean code). Use these to prove baseline functionality.
*   **200 "Dev Tooling" Samples:** Packages classified as linters, CLIs, scaffolders, or build tools.
    *   *Why:* These legitimate tools *often* read files, spawn shells, and make network calls. They are the hardest to distinguish from malware.
*   **200 "Niche" Samples:** Packages with < 500 stars but > 1 year of maintenance.
    *   *Why:* "Messy" amateur code often uses `evil-looking` practices like `eval()` for legitimate reasons.

### Instruction D: Sanitize the Payload, Not the Structure
**Critique:** Sanitization often accidentally removes the *detection signal* (the obfuscation), making the sample useless for training the scanner.
**Action:** preserve the "wrapper" when creating `dataset/sanitized_samples/`.

*   **Bad Sanitization:**
    *   *Original:* `eval(base64_decode("malicious_code"))`
    *   *Bad Fix:* `console.log("malicious code removed")` -> **WRONG**. You lost the `eval` + `base64` signal.
*   **Correct Sanitization:**
    *   *Correct Fix:* `eval(base64_decode("console.log('safe payload')"))`
    *   *Outcome:* The Code *structure* (obfuscation + dynamic execution) remains, triggering the scanner, but the *action* is safe.

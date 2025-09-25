# Methodology Refinements

These notes document critical refinements applied during Phases 1 & 2 to ensure academic rigor and valid dataset construction.

## 1. Taxonomy Refinement (Phase 1)
To ensure clarity, the research must strictly distinguish between **Techniques** and **Objectives**.

### Retagging "Token Theft" vs "Env Var Access"
*   **Technique (TTP):** The code pattern observed (e.g., `process.env` read, file read of `~/.ssh`).
*   **Objective (Impact):** The adversary's goal (e.g., Credential Harvesting, Lateral Movement).

### Explicit Inclusion of "Build-Time Tampering"
The definition of "Lifecycle Scripts" has been expanded to include:
*   `Makefile` (targets like `all:`, `install:`)
*   `build.rs` (Rust remote execution)
*   `setup.py` / `__init__.py` (Python execution)
This demonstrates ecosystem-agnostic design, even if the prototype focuses on JS/Python.

## 2. Dataset Validity (Phase 2)
To avoid selection bias in the benign dataset, we avoided scanning only the top 500 popular packages, which are typically "too clean" to be representative.

### The "Long Tail" Sampling Strategy
The 800 benign samples were split as follows:
*   **400 "Standard" Samples:** Top starred repos (Baseline).
*   **200 "Dev Tooling" Samples:** Linters, CLIs, Scaffolders. These legitimate tools often use suspect features (shell, file access).
*   **200 "Niche" Samples:** Low-star (< 500) maintained packages. These often contain "messy" code (e.g. legitimate `eval` usage).

### Sanitization Policy
When creating sanitized samples, we preserve the **wrapper** (detection signal) while neutralizing the payload.
*   **Method:** Keep `eval(base64(...))` structure but replace the inner encoded string with safe code (e.g., `console.log('safe')`). creates a harmless valid signal for the scanner testing.

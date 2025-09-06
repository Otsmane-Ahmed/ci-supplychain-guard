# CI/CD Integration Designs

This directory contains the architectural specifications for integrating the CI-Guard system into production CI/CD pipelines (e.g., GitHub Actions, GitLab CI). It defines the logic flow, decision thresholds, and required environment variables.

## Files

### 1. `CI_FLOW_DESIGN.md`
**Type:** Architecture Specification
**Function:**
* Defines the **"Traffic Light Protocol"** logic used to automate blocking decisions.
* **Workflow:**
    1.  **Fetch:** Identify changed files in a Pull Request.
    2.  **Scan:** Run Static Analysis.
    3.  **Static Eval:**
        * Score $\le$ 3: **PASS** (Green)
        * Score $\ge$ 10: **BLOCK** (Red)
        * Score 4-9: **TRIGGER SANDBOX** (Yellow)
    4.  **Dynamic Eval:** If sandboxed, check for honeytoken access.
    5.  **Final Decision:** Block malicious behavior or Warn on suspicious non-events.
* Lists required environment variables (e.g., `GITHUB_TOKEN`) and exit codes.

## Usage
These templates serve as the blueprint for the actual workflow implementation found in `.github/workflows/guard.yml`. Use these designs when porting the tool to other CI systems (e.g., Jenkins, Travis CI).

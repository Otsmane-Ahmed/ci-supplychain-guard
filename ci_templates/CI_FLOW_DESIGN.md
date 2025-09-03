# CI Integration Specification

## 1. Workflow Logic
**Trigger:** Pull Request (Open / Synchronize)

| Step | Action | Condition | Result |
| :--- | :--- | :--- | :--- |
| **1. Fetch** | Retrieve changed files | N/A | File list |
| **2. Scan** | Execute `static_scanner.py` | All changed files | Static Score (0-100) |
| **3. Static Eval** | Score <= 3 | - | PASS |
| | Score >= 10 | - | BLOCK |
| | Score 4-9 | - | TRIGGER SANDBOX |
| **4. Dynamic Eval** | Execute `sandbox_runner.py` | If Score 4-9 | Verdict (SAFE / MALICIOUS) |
| **5. Final Decision** | Verdict = MALICIOUS | - | BLOCK |
| | Verdict = SAFE | - | WARNING (Manual Review) |

## 2. Environment Variables
* `GITHUB_TOKEN`: Required for posting PR comments.
* `DECEPTION_SECRETS`: Optional overrides for honeytokens.

## 3. Exit Codes
* `0`: Pass (Safe or Warning)
* `1`: Fail (Block)

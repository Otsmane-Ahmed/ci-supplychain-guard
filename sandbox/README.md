# Active Deception Sandbox

This module implements the dynamic analysis engine ("The Trap") for the CI-Guard system. It executes suspicious code within an isolated, instrumented container designed to mimic a developer's workstation ("Active Deception").

## Core Methodology
The sandbox relies on two key strategies to detect advanced malware that evades standard analysis:
1.  **Isolation:** Execution occurs in a network-restricted Docker container to prevent actual exfiltration.
2.  **Masquerading:** The environment is populated with fake user artifacts (bash history) and "Honeytokens" (decoy credentials). Accessing these decoys serves as a high-fidelity indicator of malicious intent.

## Directory Structure

### 1. `sandbox_runner.py`
**Type:** Orchestration Script
**Function:**
* **Builds** the Docker image defined in `Dockerfile`.
* **Executes** the target package using `npm install` inside the container.
* **Monitors** system calls using `strace` (attached to the parent process).
* **Parses** the resulting logs to detect:
    * File access to honeytokens (`~/.ssh/id_rsa`, `~/.aws/credentials`).
    * Network socket creation (`connect`, `AF_INET`).
* **Verdict:** Returns `MALICIOUS` if honeytokens are touched, `SUSPICIOUS` for network attempts, or `SAFE`.

### 2. `Dockerfile`
**Type:** Environment Definition
**Function:**
* Builds the Linux environment (Node.js base).
* **Deception:** Creates a non-root user `dev_user` to simulate a real developer.
* **Honeytokens:** Injects fake AWS credentials and SSH keys into standard locations (`~/.ssh/`, `~/.aws/`).
* **Fake History:** Populates `~/.bash_history` with realistic commands (`git clone`, `npm install`) to fool anti-sandbox checks.

### 3. `SANDBOX_DESIGN.md`
**Type:** Architecture Specification
**Function:**
* Documents the technical design constraints.
* **Isolation:** Defines network restrictions (`--network none`) and resource limits (1 CPU, 512MB RAM).
* **Privileges:** Enforces non-privileged execution (dropping root).
* **Instrumentation:** Lists the specific syscalls monitored by `strace` (`open`, `openat`, `access`, `connect`, `execve`).

### 4. `__init__.py`
**Type:** Configuration
**Function:**
* Exposes the `build_sandbox` and `run_sample` functions to the main application (`main_guard.py`).

## Usage

This module is typically invoked by `main_guard.py` when the Static Analyzer assigns a "Suspicious" score (4-9). It can also be run independently for testing.

```bash
# Run from the project root
python3 sandbox/sandbox_runner.py path/to/suspicious/package
```

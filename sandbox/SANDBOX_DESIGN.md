# Sandbox Architecture Specification

## 1. Isolation Strategy
* **Runtime:** Docker (Proot/Sysbox compatible for unprivileged CI execution).
* **Constraints:**
    * Network: `none` (Air-gapped).
    * CPU: 1 Core.
    * Memory: 512MB.
* **Privileges:** Non-root execution (`USER dev_user`).

## 2. Deception Strategy (Masquerading)
To detect anti-analysis malware, the environment mimics a developer workstation:
1.  **User Simulation:** Creates `dev_user` with populated `~/.bash_history`.
2.  **Honeytokens:** Injects fake credentials at standard paths:
    * `~/.ssh/id_rsa`
    * `~/.aws/credentials`
    * `~/.npmrc`

## 3. Instrumentation
* **Tool:** `strace` attached to the parent process.
* **syscalls monitored:**
    * `open`, `openat`, `access`: File system enumeration.
    * `connect`: Network socket creation.
    * `execve`: Process spawning.

## 4. Execution Protocol
1.  Mount target package to `/app`.
2.  Execute installation scripts (`npm install`).
3.  Terminate after 30s timeout.
4.  Parse logs for honeytoken access or network egress.

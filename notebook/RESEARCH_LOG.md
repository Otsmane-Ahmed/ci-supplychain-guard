Introduction
    
- Problem Statement :
	-**1. The Escalating Threat:** Supply-chain attacks have shifted left, targeting the Continuous Integration (CI) pipeline itself (e.g., _tj-actions_, _Codecov_); however, developers inherently trust build commands like `npm install` to run safely within their privileged infrastructure, creating a massive blind spot.
	-**2. The Detection Gap:** Current defenses are either reactive (scanning published artifacts _after_ a compromise has occurred) or too resource-intensive for the "Pre-Merge" phase (e.g., full heavy sandboxing like Cuckoo), failing to detect malicious lifecycle scripts before they exfiltrate secrets.
	-**3. The Need for Lightweight Defense:** Open-source maintainers currently lack a low-friction, automated tool that can detect malicious intent in Pull Requests (such as environment variable exfiltration or obfuscation) without significantly slowing down the development workflow or requiring complex infrastructure.
    
- Research Questions :
- **RQ1: Static Analysis Effectiveness**
	- **Question:** How effective are static heuristics (regex, AST analysis) at detecting known patterns of malicious CI modifications compared to obfuscated attacks?
	- **Hypothesis:** We hypothesize that static analysis will achieve high recall (>90%) on simple "low-hanging fruit" attacks (e.g., hardcoded IP addresses, known malicious package names) but will fail significantly (<40% recall) against obfuscated payloads (e.g., base64 encoding, dynamic imports).
- **RQ2: Dynamic Sandboxing Value**
	- **Question:** To what extent can lightweight dynamic sandboxing identify evasion techniques (e.g., obfuscation, external fetches) that bypass static analysis?
	- **Hypothesis:** We expect that a short-duration sandbox (running for <15 seconds during install) will detect 100% of network-based exfiltration attempts that static analysis misses, specifically catching "curl-pipe-bash" attacks and DNS exfiltration.
- **RQ3: Operational Trade-offs**
	- **Question:** What is the trade-off between detection capability and developer friction (runtime overhead, false positives) in a hardened CI pipeline?    
	- **Hypothesis:** We propose that a "Funnel Architecture" (running heavy sandboxing _only_ when static analysis flags a risk) can keep the average CI overhead under 30 seconds while maintaining a false positive rate below 5%, making it acceptable for production use.

Threat Model
1. Attacker GoalsIntroduction
    
- Problem Statement
    
- Research Questions
…law enforcement or reputable threat intelligence sources.

Based on the analyzed incidents (e.g., Shai-Hulud, warbeast2000), the adversary aims to:

Exfiltrate Secrets: Steal CI environment variables (GITHUB_TOKEN, NPM_TOKEN, AWS_ACCESS_KEY_ID) to pivot into cloud infrastructure.

Poison Build Artifacts: Inject malicious code into the published package (e.g., dist/index.js, .dll) to compromise downstream users.

Establish Persistence: Modify repository files (e.g., adding a malicious GitHub Action workflow) to maintain access even after the initial malicious PR is closed.

2. Attacker Capabilities
We assume the attacker falls into one of two categories:

Malicious Contributor (The "PR Attacker"):

Can fork the repository and submit Pull Requests.

Can modify source code, configuration files (package.json), and build scripts.

Constraint: Cannot directly modify protected branches or Repository Secrets without a merged PR.

Compromised Maintainer (The "Account Takeover"):

Has write access to the repository and package registry (npm/PyPI).

Can push directly to main or publish new versions without code review.

Scope Note: Our defense primarily targets the Malicious Contributor (Pre-Merge) but acts as a secondary check for Compromised Maintainers if CI scans are enforced on push.

3. Defender Assumptions
The CI Runner is Ephemeral: We assume the CI environment is clean at the start of the job.

The Scanner Runs First: The defense tool (Static Analyzer) executes before the installation of untrusted dependencies (npm install).

Network Visibility: The defense mechanism has the ability to monitor or restrict network traffic within the CI container (e.g., via Docker network policies).

4. Out of Scope
Endpoint Compromise: Malware executing on the developer's local laptop is out of scope. We focus strictly on the CI/CD pipeline.

Zero-Day Kernel Exploits: Attacks that escape the Docker container via kernel vulnerabilities are assumed to be handled by the cloud provider.

Social Engineering: Phishing attacks that trick a maintainer into manually approving a malicious PR are out of scope for technical detection, though our tool aims to flag the risk.

- Evidence Log :
| Incident Name                                                                             | Ecosystem                             | Attack Vector                                                                                                             | Maintainer Compromise                                                             | Lifecycle Abuse                                                                                                 | Token Theft                                                                                          | Obfuscation                                                                                  | CI Exploitation                                                                                                                       | Files Modified                                                                                                    | Impact                                                                                                                                                                                                              | link                                                                                                                                         |
| ----------------------------------------------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Malicious Nx Package Versions (Duplicate Advisory Reference)                              | npm                                   | Malicious package versions published to npm (supply-chain attack)                                                         | Likely yes (unauthorized publication)                                             | Yes (malicious code injected into package scripts)                                                              | Yes (credential stealing + GitHub exfiltration)                                                      | Yes (tampered code designed to hide intent)                                                  | Yes (CI environments running Nx would leak tokens)                                                                                    | Modified `scripts/build.js` and injected `preinstall` in `package.json`, plugins, filesystem-scanning malware     | Theft of credentials and posting them to GitHub under victims’ accounts, large-scale supply-chain compromise.                                                                                                       | [GHSA-8mjq-32x3-22qf](https://github.com/advisories/GHSA-8mjq-32x3-22qf)                                                                     |
| Malicious debug@4.4.2 dependency impacting MetaMask SDK                                   | npm                                   | Malicious transitive dependency (debug@4.4.2) published to npm                                                            | Likely yes (unauthorized package publication)                                     | Yes (malicious JS executed during dependency load)                                                              | Not exactly tokens, but attempted manipulation of wallet communication (credential/transaction risk) | Yes (injected code hidden inside familiar package)                                           | Yes (builds pulling dependencies during attack window executed malicious debug)                                                       | debug package files tampered with malicious code                                                                  | Downstream dApps using MetaMask SDK pulled malicious code, enabling communication tampering and potential theft or manipulation.                                                                                    | [GHSA-qj3p-xc97-xw74](https://github.com/advisories/GHSA-qj3p-xc97-xw74)                                                                     |
| Prebid.js malicious version (10.9.2)                                                      | npm                                   | Malicious package version published to npm                                                                                | Yes (phishing to gain unauthorized access for publishing)                         | Yes (executed malicious JS during use)                                                                          | Yes (npm maintainer tokens stolen via phishing)                                                      | Yes (obfuscated code to hide wallet hijacking logic)                                         | No explicit (malware runs client-side in browser, not on install)                                                                     | Distribution files (e.g., bundled JS with hooked XMLHttpRequest)                                                  | Redirected crypto transactions (e.g., ETH, BTC) to attacker; low actual theft, but risk to ad tech apps using it (98 downloads)                                                                                     | [GHSA-jwq7-6j4r-2f92](https://github.com/advisories/GHSA-jwq7-6j4r-2f92)                                                                     |
| DuckDB npm packages compromise (1.3.3 / 1.29.2)                                           | npm                                   | Maintainer phishing → malicious package versions published to npm                                                         | Yes (phishing via fake npm login portal)                                          | Yes (malicious JS inside package builds)                                                                        | Yes (stolen npm API token used to publish malware)                                                   | Yes (hidden malicious modifications to build system)                                         | Yes (CI installs would run infected versions)                                                                                         | Node.js build files, WASM bindings, API modules                                                                   | Malicious DuckDB versions redirected crypto transactions, affected CI builds, and propagated downstream via common dependencies.                                                                                    | [GHSA-w62p-hx95-gf2c](https://github.com/advisories/GHSA-w62p-hx95-gf2c)                                                                     |
| Malicious Nx Versions Supply-Chain Attack (s1ngularity-repository incident)               | npm                                   | Malicious versions published after CI workflow compromise + maintainer credential theft                                   | Yes (phishing + malicious PR exploiting pull_request_target)                      | Yes (postinstall script scanning filesystem + modifying shell rc files)                                         | Yes (npm token stolen through malicious GitHub Actions workflow)                                     | Medium (malicious telemetry.js hidden inside package)                                        | **Yes, major** , pull_request_target + bash injection → triggered publish workflow → extracted npm token → attacker published malware | telemetry.js, package.json scripts, publish.yml, CI workflow files                                                | Credential theft, GitHub repo creation on victim accounts, modification of ~/.bashrc and ~/.zshrc, potential machine shutdown, widespread propagation via VSCode Nx Console                                         | [GHSA-cxm3-wv7p-598c](https://github.com/advisories/GHSA-cxm3-wv7p-598c)                                                                     |
| Shai-Hulud npm Worm (2025)                                                                | npm                                   | Self-replicating worm injected via compromised npm developer accounts                                                     | Yes  npm maintainer accounts compromised (phishing / token theft)                 | Yes malicious postinstall script auto-added to package.json; autospreading to all packages maintained by victim | Yes npm, GitHub, AWS, GCP tokens stolen (TruffleHog embedded)                                        | Medium malicious bundle.js is large, partially obfuscated                                    | Yes creates malicious GitHub Actions workflows (.github/workflows/shai-hulud-workflow.yml)                                            | Modified package.json, injected bundle.js, created public “-migration” repos, new GitHub branches, workflow files | Hundreds of npm packages compromised; millions of downloads; automatic worm propagation; exfiltration of secrets; private repos exposed; large-scale supply chain compromise                                        | [ReversingLabs Shai-Hulud](https://www.reversinglabs.com/blog/shai-hulud-worm-npm)                                                           |
| Ethereum Smart-Contract Loader Campaign (colortoolsv2 / mimelib2)                         | npm + GitHub                          | Malicious npm packages using _Ethereum smart contracts_ to host C2 commands; fake GitHub repos used to lure developers    | No direct maintainer compromise, but fake maintainer ecosystem built to deceive   | Yes (malicious downloader inside npm package executed on install/use)                                           | no                                                                                                   | Yes (obfuscated JS payload fetching encrypted C2 URL from blockchain)                        | Indirectly, GitHub repos with fake commit activity used to push the packages                                                          | index.js downloader, malicious code inside npm package                                                            | Downloaded second stage malware via URLs stored in blockchain, bypassing URL-based detection. Large campaign across GitHub with fake stars, forks, commits, and trading-bot repos to trick developers               | [ReversingLabs Ethereum Contracts](https://www.reversinglabs.com/blog/ethereum-contracts-malicious-code)                                     |
| ethers-provider2 and ethers-providerz Reverse Shell Campaign                              | npm                                   | Malicious packages mimicking ssh2 and patching local ethers package                                                       | No, packages were malicious from creation                                         | Yes, install script patches legitimate package files                                                            | no                                                                                                   | Some obfuscation in stage downloads                                                          | CI running npm install executes malicious install.js                                                                                  | provider-jsonrpc.js replaced, loader.js created, patched JS files                                                 | Remote reverse shell, persistent infection even after removal, corruption of popular ethers dependency                                                                                                              | [ReversingLabs Reverse Shell](https://www.reversinglabs.com/blog/malicious-npm-patch-delivers-reverse-shell)                                 |
| warbeast2000 and kodiak2k SSH-key exfiltration campaign                                   | npm                                   | Malicious packages with postinstall script fetching second-stage JS that exfiltrates SSH keys                             | No maintainer hijack. Packages created malicious from the start                   | Yes. Postinstall used to run remote code and fetch payload                                                      | Indirect: SSH private keys stolen, enabling GitHub repo takeover                                     | Light obfuscation (Base64 + remote fetch)                                                    | None documented                                                                                                                       | No modification of dependency chains, but reads ~/.ssh/id_rsa or custom key and uploads                           | Theft of SSH keys, potential full compromise of developer GitHub accounts and downstream supply-chain trust                                                                                                         | [The Hacker News warbeast2000](https://thehackernews.com/2024/01/malicious-npm-packages-exfiltrate-1600.html)                                |
| Colorama / Colorizr Cross-Ecosystem Typosquatting Backdoor Campaign                       | PyPI (with NPM name-confusion)        | Typosquatting + cross-ecosystem name confusion (PyPI packages mimicking NPM “colorizr”)                                   | No (malicious packages newly created)                                             | Yes (install-time execution, multi-stage payloads)                                                              | Yes (environment variables, config secrets, SSH keys, registry secrets)                              | Yes (Base64 payloads, hidden execs, encoded URLs)                                            | Not directly CI-targeted, but CI installing package would run payloads                                                                | Windows: scheduled tasks, registry, AV settings; Linux: systemd, crontabs, rc.local, temporary files in /tmp      | Remote access backdoor on Windows & Linux; gs-netcat encrypted exfiltration; persistence; AV evasion; high-grade backdoor; multi-actor campaign; cross-ecosystem deception                                          | [GBHackers Typosquatting](https://checkmarx.com/zero-post/python-pypi-supply-chain-attack-colorama/)                                         |
| itayamar WordPress Plugin S3 Backdoor (CVE-2025-8047)                                     | WordPress Plugins (PHP + external JS) | Compromised external JS loaded from abandoned S3 bucket                                                                   | No direct maintainer hijack; plugin loads remote untrusted JS                     | Yes (runtime code injection via untrusted third-party JS)                                                                       | no                                                                                                   | No obfuscation, but remote JS fully attacker-controlled                                      | none                                                                                                                                  | No local files modified; malicious JS loaded remotely                                                             | Backdoor capability, ability to run arbitrary JS on all sites using the plugins; forced popups; paywall-based allowedDomains list; vulnerable plugins with no fix; long-term supply-chain exposure                  | [CVE-2025-8047](https://www.cve.org/CVERecord?id=CVE-2025-8047)                                                                              |
| eslint-config-prettier Compromise (CVE-2025-54313)                                        | npm                                   | Malicious versions published after maintainer phishing via fake npm login page                                            | Yes (stolen npm token)                                                            | Yes (postinstall JS executed node-gyp.dll malware)                                                              | No direct token theft, but DLL allowed full RCE                                                      | Light obfuscation; malicious DLL hidden inside package tarball                               | Yes, on Windows CI runners  npm install runs DLL                                                                                      | install.js, embedded node-gyp.dll                                                                                 | RCE on Windows developers/CI hosts; compromise of major ecosystem-wide linting tool with ~30M weekly downloads                                                                                                      | [CVE-2025-54313](https://www.cve.org/CVERecord?id=CVE-2025-54313)                                                                            |
| aiocpa malicious update (0.1.13 / 0.1.14)                                                 | PyPI                                  | Malicious updated package published to PyPI (source repo kept clean to evade detection)                                   | _Unknown_ (either original author or compromised account)                         | Yes malicious payload injected into module import workflow (utils/sync.py executed on import)                   | Yes exfiltrates private keys + constructor arguments via Telegram bot                                | Yes 50 recursive layers (base64 + zlib)                                                      | Yes any CI that installs or imports aiocpa leaks secrets                                                                              | cryptopay/utils/sync.py, __init__.py                                                                              | Exfiltration of private keys and crypto API tokens; potential theft of funds and compromise of developer systems; ~4k downloads before removal                                                                      | [Phylum aiocpa](https://blog.phylum.io/python-crypto-library-updated-to-steal-private-keys/)                                                 |
| Shai-Hulud 2.0 / Bun Runtime Poisoning (2025)                                             | npm + GitHub                          | Mass poisoning: thousands of malicious updates using fake “Bun runtime” feature (preinstall → setup_bun.js)               | Yes (compromised npm accounts OR stolen tokens used for auto-publish)             | Yes preinstall script executes bun_environment.js (10MB payload)                                                | **Yes** TruffleHog-based scanning leaks GitHub, npm, AWS/GCP/Azure secrets                           | **YES heavy obfuscation** (10MB JS blob, dynamic execution, encoded payloads)                | YES major CI compromise (creates malicious GitHub Action runner + workflow to steal secrets)                                          | package.json, setup_bun.js, bun_environment.js, `.github/workflows/formatter_*.yml`                               | 1k+ poisoned npm packages; **27k+ GitHub repos infected**; mass exfiltration of secrets; worm-like propagation across entire ecosystem                                                                              | [Datadog Shai-Hulud 2.0](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)                                                 |
| Top.gg Repo Poisoning via Rogue Colorama Variant (2022–2024 multi-year PyPI campaign)     | PyPI + GitHub                         | Trojanized Colorama package delivered via typosquatting + rogue PyPI uploads + fake GitHub repos                          | Yes maintainer account hijacked via cookie/session theft (editor-syntax)          | **Yes** malicious code inserted into `__init__.py`, executed at install time                                    | **Yes** browser cookies, Discord tokens, Telegram sessions, wallet keys, GitHub tokens               | **Yes** padding to hide code, zlib compression, foreign-language variable names              | **Indirect CI risk** (any CI installing the rogue package leaks env vars / tokens)                                                    | `__init__.py`, dependency injection in `requirements.txt`, commits injected in top-gg/python-sdk                  | Infection of legitimate GitHub repos (Top.gg SDK), theft of developer GitHub cookies, multi-year campaign, multi-stage trojan payload, cross-ecosystem propagation                                                  | [CSO Online Top.gg](https://www.csoonline.com/article/2075172/software-supply-chain-attack-impacts-repo-of-large-discord-bot-community.html) |
| tj-actions/changed-files GitHub Action Supply-Chain Compromise (CVE-2025-30066)           | GitHub Actions / CI/CD                | Malicious commit injected into a widely used GitHub Action; retroactive tag poisoning                                     | **Yes** attacker stole maintainer's GitHub PAT used by `@tj-actions-bot`          | no lifecycle scripts; attack occurs inside CI workflow                                                          | **Yes** CI secrets printed to logs (AWS keys, GitHub PATs, npm tokens, SSH keys)                     | Medium (malicious Python script fetched from hidden GitHub gist)                             | **YES, major**  action executed inside CI of 23k+ repos, leaking secrets to workflow logs                                             | Modified action YAML, version tags retargeted to malicious commit                                                 | Exposure of secrets across 23,000+ repos; risk of repo takeover, cloud account compromise, npm token misuse; ecosystem-wide trust break                                                                             | [The Hacker News tj-actions](https://thehackernews.com/2025/03/github-action-compromise-puts-cicd.html)                                      |
| qix Maintainer Account Compromise (ansi-styles, chalk, supports-color, debug, etc.)  2025 | npm                                   | Maintainer hacked → attacker published dozens of malicious package version                                                | **YES**  maintainer account hijacked via phishing; attacker locked maintainer out | Yes  packages contained payloads executed on import/install                                                     | Yes payload harvested browser creds, machine secrets, crypto-wallet data, possibly developer tokens  | Likely medium obfuscation (packed payloads inside published tarballs)                        | Not directly CI-targeting but **CI installing compromised versions leaks secrets**                                                    | Many JS files inside affected packages modified; payload added to core modules                                    | Massive ecosystem-wide compromise: foundational libraries impacted; thousands of downstream packages at risk; opportunity for widespread secret theft, wallet manipulation, malicious code injection                | [Orca Security qix](https://orca.security/resources/blog/qix-npm-attack/)                                                                    |
| Malicious Rust Crates (faster_log and async_println, 2025)                                | Rust / crates.io                      | Typosquatting plus clone of legitimate fast_log crate with hidden malicious code                                          | No (attacker created new crates)                                                  | Yes (malicious runtime logging routines that scan files and send secrets)                                       | Yes (Solana and Ethereum private keys exfiltrated)                                                   | Light (malicious code mixed inside normal logging functions)                                 | Indirect: CI that runs tests or executes code using these crates leaks secrets                                                        | Modified Rust source files inside the fake crates                                                                 | Theft of crypto wallet private keys, 8424 downloads, risk to developer machines and CI systems, Rust ecosystem supply chain compromise                                                                              | [The Hacker News Rust Crates](https://thehackernews.com/2025/09/malicious-rust-crates-steal-solana-and.html)                                 |
| sisaws & secmeasure SilentSync RAT campaign (2025)                                        | PyPI                                  | Typosquatting + impersonation of legitimate `sisa` package + malicious functions in `__init__.py` downloading RAT payload | No (attacker created new malicious packages)                                      | Yes (malicious functions inside `__init__.py`, executed at import-time)                                         | Yes (browser credentials, cookies, autofill, and saved passwords stolen by RAT)                      | Medium (hex-encoded curl command + encoded IP + hidden malicious logic in wrapper functions) | Yes (CI importing or running these packages would download & execute SilentSync RAT, leak credentials)                                | `__init__.py` modified to embed downloader; helper.py dropped at runtime; SilentSync RAT executed                 | Delivery of SilentSync RAT with remote command execution, file exfiltration, screenshots, browser credential theft; Windows-focused but supports Linux/macOS persistence; risk to CI systems and developer machines | [Zscaler SilentSync](https://www.zscaler.com/blogs/security-research/malicious-pypi-packages-deliver-silentsync-rat)                         |
| solana PyPI Multi-Package Malware Campaign (2025)                                         | PyPI                                  | Typosquatting + multi-package malicious uploads (solana-test, solana-data, solana-live, etc.)                             | No (malicious actor created new packages)                                         | Yes (runtime monkey-patching to steal keys)                                                                     | Yes (Solana wallet keys + code exfil)                                                                | Light to medium (hidden inside helper modules)                                               | Possible (if CI installs malicious packages, secrets leak)                                                                            | Modified runtime modules, injected monkey-patches                                                                 | Theft of crypto wallet keys, source code exfiltration, multi-package coordinated attack                                                                                                                             | [The Hacker News Solana PyPI](https://thehackernews.com/2025/05/malicious-pypi-package-posing-as-solana.html)                                  |
| semantic-types Dependency Hijacking (solana-keypair, soltrade)                            | PyPI                                  | Dependency-chain hijack (malicious packages depend on semantic-types to trigger key-stealing payload)                     | Unknown (original author may be clean; attacker added downstream packages)        | Yes (malicious code injected via monkey-patching during import)                                                 | Yes (Solana wallet keys stolen during development + CI builds)                                       | Medium (hidden inside dependency layers)                                                     | Yes (CI installing these packages triggers secret theft)                                                                              | Runtime-patched semantic-types functions                                                                          | High-severity multi-layer supply-chain compromise                                                                                                                                                                   | [CyberPress semantic-types](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)                                        |
| Alibaba AI SDK Impersonation Malware (2025)                                               | PyPI                                  | Fake AI SDK packages containing malicious Pickle payloads                                                                 | no                                                                                | Yes (Pickle RCE executed on import)                                                                             | Yes (sensitive developer data harvested)                                                             | Medium (payload hidden inside zipped Pickle models)                                          | Yes (CI importing model triggers RCE)                                                                                                 | Malicious .pt / .pkl payloads executed on load                                                                    | RCE on import, credential theft, data exfiltration                                                                                                                                                                  | [AIBase Alibaba SDK](https://hackread.com/malware-ai-models-pypi-targets-alibaba-ai-labs-users/)                                                                                   |
| RubyGems Fastlane Telegram Proxy Exfiltration (2025)                                      | RubyGems                              | Typosquatting legitimate Fastlane Telegram plugin                                                                         | no                                                                                | Yes (runtime API endpoint replacement)                                                                          | Yes (Telegram auth tokens + messages + files)                                                        | Low (simple endpoint switch)                                                                 | Possible (CI using Fastlane leaks secrets)                                                                                            | Modified API endpoint inside plugin                                                                               | Full Telegram session hijacking, message and credential exfiltration                                                                                                                                                | [BleepingComputer Fastlane](https://socket.dev/blog/malicious-ruby-gems-exfiltrate-telegram-tokens-and-messages-following-vietnam-ban)   |
| BSC/Ethereum npm Malicious Packages Cluster (2021–2025 active)                            | npm                                   | Typosquatting + crypto skimming + destructive scripts                                                                     | no                                                                                | Yes (runtime transaction interception + destructive FS operations)                                              | Yes (wallet skim + private keys)                                                                     | Light (hidden inside transaction logic)                                                      | Possible (CI running builds may send transactions)                                                                                    | Modified JS transaction logic; destructive FS ops                                                                 | Diverted crypto transactions; ability to delete entire project dirs (xlsc-to-json-lh)                                                                                                                               | [Socket.dev BSC/Ethereum](https://socket.dev/blog/malicious-npm-packages-target-bsc-and-ethereum)                                      |
| Zapier AI Actions Malicious Package (CVE-2025-374)                                        | npm                                   | Malicious package `@zapier/ai-actions` containing malware                                                                 | Yes (supply chain attack)                                                         | Yes (preinstall script execution)                                                                               | Yes (credential harvesting)                                                                          | Unknown                                                                                      | Yes (CI/CD pipelines using this package would be compromised)                                                                         | Modified package files                                                                                            | Credential theft, compromise of GitHub and npm repositories                                                                                                                                                         | [Snyk Zapier](https://security.snyk.io/vuln/SNYK-JS-ZAPIERAIACTIONS-14103233)                                                                |
| Multiple Malicious Packages on PyPI, NPM, and RubyGems                                    | PyPI, NPM, RubyGems                   | Typosquatting and brandjacking                                                                                            | No                                                                                | Yes (malicious payloads in fake packages)                                                                       | Yes (crypto wallet theft, Telegram data)                                                             | Yes                                                                                          | Yes (CI using these packages would run malware)                                                                                       | Various files in fake packages                                                                                    | Theft of funds, deletion of codebases, Telegram data exfiltration                                                                                                                                                   | [Cloudsmith Multiple Packages](https://cloudsmith.com/blog/multiple-malicious-packages-discovered-on-pypi-npm-and-rubygems)                  |

## Incident Categorization & Analysis

### Lifecycle Script Abuse
**Incidents:**
- Shai-Hulud npm Worm
- warbeast2000
- Zapier AI Actions
- Shai-Hulud 2.0 / Bun Runtime Poisoning

**Techniques:**
- **Preinstall/Postinstall Injection:** Injecting malicious commands (e.g., `curl`, `wget`, `bash`) into `preinstall` or `postinstall` scripts in `package.json` to execute code automatically upon installation.
- **Shell Command Execution:** Using shell operators (`&&`, `|`) to chain malicious commands with legitimate ones.

**Indicators:**
- Presence of `preinstall`, `postinstall`, or `install` scripts in `package.json` that invoke network utilities or obfuscated commands.
- Scripts executing encoded strings (e.g., `echo <base64> | base64 -d | bash`).

**Detection Methods:**
- **Static Detection:** Scan `package.json` files for suspicious script lifecycle hooks and high-entropy strings or network commands.
    - *Tools:* `npm audit`, `lockfile-lint`, `semgrep` (custom rules for `preinstall`).
- **Dynamic Detection:** Monitor process execution trees during `npm install` to detect unexpected shell spawning or network connections.
    - *Tools:* `strace`, `falco` (monitor `execve` calls from `npm`), `sysdig`.

### Maintainer Account Compromise
**Incidents:**
- Malicious Nx Package Versions (Duplicate Advisory)
- Prebid.js malicious version
- DuckDB npm packages compromise
- eslint-config-prettier Compromise
- qix Maintainer Account Compromise

**Techniques:**
- **Phishing:** Deceiving maintainers into revealing credentials or tokens (e.g., fake npm login pages).
- **Token Theft:** Stealing active session tokens or API keys from developer environments.
- **Account Takeover:** Gaining control of a maintainer's account to publish malicious versions of legitimate packages.

**Indicators:**
- Unexpected package releases from new IP addresses or geographic locations.
- Version bumps without corresponding commits or tags in the source repository.
- Releases that break existing package signing keys (if applicable).

**Detection Methods:**
- **Static Detection:** Compare the published package version against the source code repository (Source-to-Artifact correspondence).
    - *Tools:* `diff` (source vs artifact), `npm diff`.
- **Dynamic Detection:** Monitor registry transparency logs for anomalous publishing behavior (e.g., rapid version releases, releases by new user accounts).
    - *Tools:* `Socket.dev` alerts, `Phylum` monitoring.

### Malicious Dependency Injection
**Incidents:**
- Malicious debug@4.4.2 dependency
- ethers-provider2
- Colorama / Colorizr
- Top.gg Repo Poisoning
- Malicious Rust Crates
- sisaws & secmeasure
- solana PyPI Campaign
- semantic-types Dependency Hijacking
- Alibaba AI SDK Impersonation
- RubyGems Fastlane Telegram Proxy
- BSC/Ethereum npm Malicious Packages
- Multiple Malicious Packages (Cloudsmith)
- itayamar WordPress Plugin S3 Backdoor

**Techniques:**
- **Typosquatting:** Registering package names that are visually similar to popular packages (e.g., `colorizr` vs `colorama`).
- **Dependency Confusion:** Uploading internal/private package names to public registries with higher version numbers.
- **Transitive Dependency Compromise:** Injecting malicious code into a deep dependency of a popular package.
- **Dynamic Payload Delivery:** Loading external malicious resources (e.g., JS from S3) at runtime.

**Indicators:**
- Package names with slight spelling variations from popular packages.
- Packages with very few downloads or recent creation dates claiming to be "official".
- Unexpected new dependencies appearing in `package-lock.json` or `yarn.lock`.

**Detection Methods:**
- **Static Detection:** Analyze `package.json` and lockfiles for known malicious packages (using vulnerability databases like OSV). Calculate Levenshtein distance to popular package names.
    - *Tools:* `OSV-Scanner`, `Dependabot`, `npm audit`.
- **Dynamic Detection:** Install packages in a sandboxed environment and monitor for suspicious behavior (e.g., accessing sensitive files).
    - *Tools:* `Cuckoo Sandbox`, `Any.Run`.

### Token Theft
**Incidents:**
- *Note:* While many incidents involve token theft as an impact (e.g., `warbeast2000`, `Shai-Hulud`), this category highlights the specific technique of targeting environment variables and credentials.

**Techniques:**
- **Environment Variable Exfiltration:** Reading `process.env` to harvest API keys, tokens, and secrets.
- **File System Scanning:** Scanning known paths (e.g., `~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`) for credentials.
- **Exfiltration via Network:** Sending stolen data to C2 servers via HTTP requests or DNS tunneling.

**Indicators:**
- Code accessing `process.env` or sensitive file paths (`.ssh`, `.aws`) without a clear functional reason.
- Network requests to unknown or suspicious domains immediately after install/import.

**Detection Methods:**
- **Static Detection:** Grep/SAST scan for patterns accessing sensitive files or environment variables.
    - *Tools:* `TruffleHog`, `Gitleaks`, `Semgrep` (rules for `process.env` access).
- **Dynamic Detection:** Use system call monitoring (e.g., eBPF, Falco) to flag reads of sensitive files by untrusted processes.
    - *Tools:* `Falco` (rule: `Read Sensitive File`), `eBPF` probes.

### Obfuscation
**Incidents:**
- Ethereum Smart-Contract Loader
- aiocpa malicious update

**Techniques:**
- **Blockchain C2:** Hiding Command & Control (C2) URLs or payloads within blockchain transactions or smart contracts to evade blocklists.
- **Source vs. Artifact Discrepancy:** Publishing clean code to GitHub but uploading a malicious version to the registry (npm/PyPI).
- **Encoding & Compression:** Using Base64, zlib, or hex encoding to hide malicious logic.

**Indicators:**
- Significant differences between the code in the source repository and the installed package.
- Presence of large blobs of encoded strings or minified code in files that should be readable.
- High entropy strings in source files.

**Detection Methods:**
- **Static Detection:** Perform entropy analysis on source files. Compare the hash/content of the installed package with the source repository.
    - *Tools:* `entropy` checkers, `diff`, `Socket` (integrity checks).
- **Dynamic Detection:** Runtime de-obfuscation (e.g., hooking `eval` or `Function` constructors) to capture the decoded payload.
    - *Tools:* JS debugging proxies, runtime instrumentation.

### CI Workflow Manipulation
**Incidents:**
- Malicious Nx Versions (s1ngularity-repository incident)
- tj-actions/changed-files GitHub Action Compromise

**Techniques:**
- **`pull_request_target` Abuse:** Exploiting the `pull_request_target` trigger to run malicious code with write permissions/secrets from a forked PR.
- **Action Tag Poisoning:** Retargeting a mutable tag (e.g., `@v1`) of a GitHub Action to a malicious commit.

**Indicators:**
- Workflows using `pull_request_target` combined with an explicit checkout of the PR's code.
- GitHub Actions referenced by mutable tags instead of immutable commit hashes.

**Detection Methods:**
- **Static Detection:** Lint workflow files (e.g., using `zizmor` or `step-security`) for insecure configurations.
    - *Tools:* `zizmor`, `actionlint`, `StepSecurity`.
- **Dynamic Detection:** Monitor CI runner logs and network traffic for unauthorized access or exfiltration.
    - *Tools:* GitHub Actions audit logs, `Harden-Runner`.

### Build-Time Tampering
**Incidents:**
- DuckDB npm packages compromise

**Techniques:**
- **Build Script Injection:** Injecting malicious code into build scripts (e.g., `Makefile`, `build.rs`, `setup.py`) that runs during the compilation/build phase.
- **Remote Resource Loading:** Fetching and executing external, untrusted resources during the build.

**Indicators:**
- Build scripts that download and execute files from the internet.
- Modifications to binary artifacts (e.g., `.dll`, `.so`, `.wasm`) that do not match the source code.

**Detection Methods:**
- **Static Detection:** Review build configuration files for network commands.
    - *Tools:* Manual code review, `semgrep`.
- **Dynamic Detection:** Enforce hermetic builds (no network access during build) and verify build reproducibility.
    - *Tools:* `Bazel` (hermetic builds), `SLSA` verification.

- ## Dataset Design

### 1. Labeling Rules

- **malicious**: Confirmed by a security advisory (GitHub/npm/PyPI) or observed malicious behavior (exfiltration/shell) in the sandbox.
    
- **benign**: No signs of malicious behavior; the repository is healthy and widely trusted.
    
- **simulated**: Ethically crafted example created by the researcher to test specific detection capabilities (e.g., evasion techniques).
    
- **unknown**: Incomplete evidence; these samples will be discarded from the final dataset.
    

### 2. Minimum Dataset Size Targets

- **Malicious (Real Historic):** ≥ 30 samples (Essential for proving real-world relevance).
    
- **Malicious (Simulated):** ≥ 150 samples (Essential for training/testing specific evasion paths).
    
- **Benign:** ≥ 800 samples (Essential to measure False Positive Rate accurately).
    

### 3. Storage Policy

- ** `dataset/private_raw/`**: Stores **RAW** malicious samples (live malware). **NEVER COMMIT TO GITHUB.**
    
- ** `dataset/sanitized_samples/`**: Stores neutralized Proof-of-Concepts (malicious code removed/replaced with dummy prints). Safe to publish.
    
- ** `dataset/schema.csv`**: The metadata index. Safe to publish.
    
- Experiments Log
    - **Prototype Design Constraint (Phase 5):** Existing dynamic analysis tools (Cuckoo, Any.Run) are too heavy for CI/CD pipelines. The prototype will implement a *lightweight custom Docker sandbox* instead of using these off-the-shelf solutions. This addresses the latency requirement for inline CI security scanning.
    
- Ethics Notes

### Responsible Disclosure
- **Vulnerability Handling:** Any vulnerabilities discovered during this research will be reported to the respective maintainers or security teams via established channels (e.g., GitHub Security Advisories, npm security contact) following a 90-day disclosure deadline policy.
- **Sensitive Data:** All personal identifiable information (PII) or credentials found in analyzed logs or malware samples will be redacted. No active exploitation of live systems will be performed.
- **Sandboxing:** All malware analysis is conducted in isolated, air-gapped virtual environments to prevent accidental spread or damage to external systems.
- **Attribution:** We avoid speculating on the identity of threat actors unless confirmed by official law enforcement or reputable threat intelligence sources.

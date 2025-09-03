# Sample Intake Protocol

## 1. Pre-Download Verification
- [ ] Isolation: Ensure working directory is excluded from git/backup.
- [ ] Network: Use VPN or isolated VM if handling live malware.

## 2. Acquisition Sources
- **Primary:** npm registry, PyPI registry.
- **Reference Datasets:**
    - MalOSS (Metadata)
    - Backstabber's Knife Collection (Historical payloads)
    - OSPtrack (Incident tracking)

## 3. Handling Procedure
1. **Download:** Use `npm pack` or `git clone` (avoid installation).
2. **Storage:** Move immediately to `dataset/private_raw/`.
3. **Analysis:** - Open with text editor only.
    - Do not execute code outside of sandbox.

## 4. Logging
- [ ] Update `schema.csv` with new sample ID.
- [ ] Record metadata (package name, version, hash).
- [ ] Label initial classification (malicious/benign).

## 5. Sanitization
- [ ] Create redacted copy in `dataset/sanitized_samples/` if needed for publication.
- [ ] Neutralize active URLs/IPs (replace with `127.0.0.1`).

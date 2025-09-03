# Use a standard Node.js image (common target for supply chain attacks)
FROM node:18-slim

# Install analysis tools (strace is our "Security Camera")
RUN apt-get update && apt-get install -y strace jq && rm -rf /var/lib/apt/lists/*

# --- FIX #2: MASQUERADING STRATEGY (Active Deception) ---

# 1. Create a fake developer user
RUN useradd -m -s /bin/bash dev_user
WORKDIR /home/dev_user

# 2. Inject Honeytokens (Fake Credentials)
# Fake SSH Key (The malware will try to steal this)
RUN mkdir -p .ssh && \
    echo "-----BEGIN OPENSSH PRIVATE KEY-----" > .ssh/id_rsa && \
    echo "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAd" >> .ssh/id_rsa && \
    echo "FAKE_KEY_FOR_RESEARCH_HONEYTOKEN_DO_NOT_USE" >> .ssh/id_rsa && \
    echo "-----END OPENSSH PRIVATE KEY-----" >> .ssh/id_rsa && \
    chmod 600 .ssh/id_rsa

# Fake AWS Credentials
RUN mkdir -p .aws && \
    echo "[default]" > .aws/credentials && \
    echo "aws_access_key_id = AKIA_FAKE_HONEYTOKEN_ID" >> .aws/credentials && \
    echo "aws_secret_access_key = FAKE_SECRET_KEY_FOR_RESEARCH" >> .aws/credentials

# Fake Bash History (To make the laptop look "real")
RUN echo "git clone https://github.com/company/repo.git" > .bash_history && \
    echo "cd repo" >> .bash_history && \
    echo "npm install" >> .bash_history && \
    echo "git commit -m 'fix bug'" >> .bash_history

# 3. Set Ownership
RUN chown -R dev_user:dev_user /home/dev_user

# --- RUNTIME CONFIG ---
# Switch to the fake user (Drop Root Privileges)
USER dev_user
WORKDIR /app

# Default entry point
CMD ["/bin/bash"]

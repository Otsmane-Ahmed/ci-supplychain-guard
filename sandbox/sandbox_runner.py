import os
import subprocess
import sys

# Configuration
DOCKER_IMAGE = "ci-guard-sandbox:latest"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOCKERFILE_PATH = os.path.join(BASE_DIR, "Dockerfile")

def build_sandbox():
    print("Building sandbox image...")
    try:
        subprocess.run(
            ["docker", "build", "-t", DOCKER_IMAGE, "-f", DOCKERFILE_PATH, BASE_DIR],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        print("Error: Docker build failed.")
        sys.exit(1)

def parse_logs(log_path):
    verdict = "SAFE"
    evidence = []
    
    if not os.path.exists(log_path):
        return "ERROR", ["Log file missing"]
        
    with open(log_path, "r", errors="ignore") as f:
        content = f.read()
        
        # Check for honeytoken access
        if ".ssh/id_rsa" in content or ".aws/credentials" in content:
            verdict = "MALICIOUS"
            evidence.append("Honeytoken access detected")
            
        # Check for network egress
        if "connect(" in content and "AF_INET" in content:
            verdict = "MALICIOUS" if verdict != "SAFE" else "SUSPICIOUS"
            evidence.append("External network connection")
            
    return verdict, evidence

def run_sample(target_dir):
    abs_path = os.path.abspath(target_dir)
    log_file = os.path.join(abs_path, "sandbox.log")
    
    # Run container with strace attached to parent process
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--cpus", "1",
        "--memory", "512m",
        "-v", f"{abs_path}:/app",
        DOCKER_IMAGE,
        "strace", "-f", "-e", "trace=open,openat,access,connect,execve", 
        "-o", "/app/sandbox.log",
        "bash", "-c", "npm install --ignore-scripts && node malicious.js"
    ]
    
    try:
        subprocess.run(cmd, timeout=30, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        print("Sandbox execution timed out.")
        
    return parse_logs(log_file)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sandbox_runner.py <target_directory>")
        sys.exit(1)
        
    build_sandbox()
    v, e = run_sample(sys.argv[1])
    
    print(f"Verdict: {v}")
    if e:
        print("Evidence:")
        for item in e:
            print(f" - {item}")

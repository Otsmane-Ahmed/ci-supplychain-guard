import os
import subprocess

TARGET_DIR = "dataset/private_raw/real_malware_extracted"

# Keywords that indicate malice but might have been missed by your Regex
SMOKING_GUNS = [
    "discord", "webhook", "eval(", "exec(", "spawn(", 
    "socket", "http.get", "https.request", "process.env",
    "dns.lookup", "ipinfo.io", "os.homedir", "base64"
]

print(f"{'PACKAGE':<40} | {'VERDICT':<10} | {'EVIDENCE FOUND IN CODE'}")
print("-" * 90)

def scan_file_for_malice(filepath):
    evidence = []
    try:
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                # Ignore super long lines (minified code) for readability
                if len(line) > 300: continue
                
                for keyword in SMOKING_GUNS:
                    if keyword in line:
                        evidence.append(f"{keyword} (line {i+1})")
    except:
        pass
    return evidence

def analyze_package(pkg_path):
    pkg_name = os.path.basename(pkg_path)
    
    # 1. Run the Guard logic quietly
    try:
        result = subprocess.run(
            ["python3", "main_guard.py", pkg_path],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout
    except:
        output = "ERROR"

    # 2. Determine Verdict
    verdict = "SAFE"
    if "Verdict: BLOCKED" in output: verdict = "BLOCKED"
    elif "Verdict: WARNING" in output: verdict = "WARNING"

    # 3. If it failed to block, find out WHY
    if verdict != "BLOCKED":
        found_clues = []
        # Search all JS/JSON files in the package
        for root, _, files in os.walk(pkg_path):
            for file in files:
                if file.endswith(".js") or file.endswith("json"):
                    clues = scan_file_for_malice(os.path.join(root, file))
                    if clues:
                        found_clues.extend(clues)
        
        # Deduplicate and limit output
        found_clues = list(set(found_clues))[:3] 
        clue_str = ", ".join(found_clues) if found_clues else "No obvious keywords found"
        
        print(f"{pkg_name[:38]:<40} | {verdict:<10} | {clue_str}")

if __name__ == "__main__":
    if os.path.exists(TARGET_DIR):
        for pkg in sorted(os.listdir(TARGET_DIR)):
            full_path = os.path.join(TARGET_DIR, pkg)
            if os.path.isdir(full_path):
                analyze_package(full_path)

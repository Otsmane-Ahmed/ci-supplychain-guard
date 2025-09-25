import subprocess
import time
import os
import csv

# --- CONFIGURATION ---
REAL_MALWARE_DIR = "dataset/private_raw/real_malware_extracted"
BENIGN_DIR = "dataset/sanitized_samples/benign_lodash/package"

def run_scan(target_path):
    start = time.time()
    try:
        # 30s timeout per sample
        result = subprocess.run(
            ["python3", "main_guard.py", target_path],
            capture_output=True, text=True, timeout=30
        )
        duration = time.time() - start
        
        if "Verdict: BLOCKED" in result.stdout:
            verdict = "BLOCKED"
        elif "Verdict: WARNING" in result.stdout:
            verdict = "WARNING"
        elif "Verdict: SAFE" in result.stdout:
            verdict = "SAFE"
        else:
            verdict = "ERROR"
            
        return verdict, duration
        
    except subprocess.TimeoutExpired:
        return "TIMEOUT", 30.0
    except Exception:
        return "CRASH", 0.0

def main():
    print(f"{'TYPE':<10} | {'PACKAGE':<40} | {'TIME':<8} | {'VERDICT':<10}")
    print("-" * 80)

    stats = {"BLOCKED": 0, "WARNING": 0, "SAFE": 0, "TOTAL": 0}

    # 1. SCAN REAL MALWARE
    if os.path.exists(REAL_MALWARE_DIR):
        for pkg in os.listdir(REAL_MALWARE_DIR):
            pkg_path = os.path.join(REAL_MALWARE_DIR, pkg)
            if os.path.isdir(pkg_path):
                verdict, duration = run_scan(pkg_path)
                
                # Update Stats
                stats["TOTAL"] += 1
                if verdict in stats: stats[verdict] += 1
                
                # Truncate name for display
                disp_name = (pkg[:38] + '..') if len(pkg) > 38 else pkg
                print(f"{'Malware':<10} | {disp_name:<40} | {duration:.4f}s | {verdict:<10}")

    print("-" * 80)
    if stats["TOTAL"] > 0:
        tpr = (stats["BLOCKED"] / stats["TOTAL"]) * 100
        print(f"[RESULTS] Detection Rate (TPR): {tpr:.1f}% ({stats['BLOCKED']}/{stats['TOTAL']})")
    else:
        print("No samples found.")

if __name__ == "__main__":
    main()

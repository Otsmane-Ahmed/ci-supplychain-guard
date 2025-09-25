#!/usr/bin/env python3
"""
Fast Benign Scanner
===================
Scans the downloaded benign packages in parallel to establish a False Positive baseline.
"""

import os
import sys
import time
import csv
import json
import subprocess
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
BENIGN_DIR = PROJECT_ROOT / "dataset" / "sanitized_samples" / "benign_top1k"
OUTPUT_FILE = PROJECT_ROOT / "full_test" / "benign_results.csv"
MAX_WORKERS = 8 # Adjust based on VPS cores

def scan_single_package(package_path):
    """
    Scans a single package directory/file using main_guard.py
    """
    pkg_name = package_path.name
    start_time = time.time()
    
    try:
        # Run the scanner
        cmd = [sys.executable, str(PROJECT_ROOT / "main_guard.py"), str(package_path)]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(PROJECT_ROOT)
        )
        duration = time.time() - start_time
        
        # Parse output
        stdout = result.stdout
        verdict = "ERROR"
        score = 0
        rules_triggered = []
        
        if "Verdict: BLOCKED" in stdout: verdict = "BLOCKED"
        elif "Verdict: WARNING" in stdout: verdict = "WARNING"
        elif "Verdict: SAFE" in stdout: verdict = "SAFE"
        
        # Extract score
        for line in stdout.splitlines():
            if "Static Risk Score:" in line:
                try:
                    score = int(line.split(":")[1].strip().split("/")[0])
                except: pass
        
        return {
            "package": pkg_name,
            "verdict": verdict,
            "score": score,
            "duration": duration,
            "error": result.stderr if result.returncode != 0 else ""
        }
        
    except subprocess.TimeoutExpired:
        return {
            "package": pkg_name,
            "verdict": "TIMEOUT",
            "score": 0,
            "duration": 60,
            "error": "Timeout"
        }
    except Exception as e:
        return {
            "package": pkg_name,
            "verdict": "ERROR",
            "score": 0,
            "duration": time.time() - start_time,
            "error": str(e)
        }

def main():
    parser = argparse.ArgumentParser(description="Fast Benign Scanner")
    parser.add_argument("--dir", default=str(BENIGN_DIR), help="Directory containing benign samples")
    parser.add_argument("--out", default=str(OUTPUT_FILE), help="Output CSV file")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help="Number of parallel threads")
    args = parser.parse_args()
    
    sample_dir = Path(args.dir)
    if not sample_dir.exists():
        print(f"[!] Directory not found: {sample_dir}")
        print("    Run 'python3 tools/download_top_packages.py' first.")
        return

    # Find samples (tarballs or directories)
    samples = list(sample_dir.glob("*.tgz")) + list(sample_dir.glob("*.zip"))
    # Also check if they are extracted directories
    for d in sample_dir.iterdir():
        if d.is_dir() and d not in samples:
            samples.append(d)
            
    print(f"[*] Found {len(samples)} samples in {sample_dir}")
    print(f"[*] Scanning with {args.workers} workers...")
    
    # Initialize CSV
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["package", "verdict", "score", "duration", "error"])
    
    results = []
    start_global = time.time()
    
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {executor.submit(scan_single_package, s): s for s in samples}
        
        completed = 0
        for future in as_completed(future_map):
            r = future.result()
            results.append(r)
            completed += 1
            
            # Real-time CSV append
            with open(out_path, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([r["package"], r["verdict"], r["score"], f"{r['duration']:.2f}", r["error"]])
            
            # Progress
            if completed % 10 == 0 or completed == len(samples):
                print(f"    [{completed}/{len(samples)}] Scanned: {r['package']} -> {r['verdict']} ({r['score']})")

    total_time = time.time() - start_global
    
    # Summary
    blocked = sum(1 for r in results if r["verdict"] == "BLOCKED")
    warnings = sum(1 for r in results if r["verdict"] == "WARNING")
    safe = sum(1 for r in results if r["verdict"] == "SAFE")
    
    print("\n" + "="*50)
    print("BENIGN SCAN COMPLETE")
    print("="*50)
    print(f"Total Scanned: {len(results)}")
    print(f"Total Time:    {total_time:.1f}s")
    print("-" * 20)
    print(f"SAFE:      {safe}")
    print(f"WARNING:   {warnings}")
    print(f"BLOCKED:   {blocked}  <-- These are potential False Positives")
    print("="*50)
    print(f"Results saved to: {out_path}")

if __name__ == "__main__":
    main()

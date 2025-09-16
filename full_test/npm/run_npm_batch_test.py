#!/usr/bin/env python3
"""
CI Supply Chain Guard - NPM Batch Tester
=========================================
Tests all 15,000+ NPM malware samples in batches of 500 to conserve disk space.

Features:
- Extracts 500 samples at a time
- Scans each sample using the CI-Guard pipeline
- Saves results in real-time (crash-safe)
- Deletes extracted samples after each batch
- Resumable: skips already-tested samples
- Detailed logging with rule breakdowns

Usage:
    python3 full_test/run_npm_batch_test.py
    python3 full_test/run_npm_batch_test.py --batch-size 200  # smaller batches
    python3 full_test/run_npm_batch_test.py --resume          # continue from last run

Author: Ahmed Otsmane
Date: December 2025
"""

import os
import sys
import json
import time
import shutil
import zipfile
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# ============================================================================
# CONFIGURATION
# ============================================================================

# Paths (relative to project root)
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
NPM_SAMPLES_DIR = PROJECT_ROOT / "dataset" / "private_raw" / "datadog_malware" / "samples" / "npm"
TEMP_EXTRACT_DIR = PROJECT_ROOT / "full_test" / "temp_extracted"
OUTPUT_DIR = PROJECT_ROOT / "full_test" / "npm_results"

# ZIP password for Datadog samples
ZIP_PASSWORD = b"infected"

# Default batch size
DEFAULT_BATCH_SIZE = 50

# ============================================================================
# OUTPUT FILES
# ============================================================================

RESULTS_CSV = OUTPUT_DIR / "npm_full_results.csv"
DETAILED_LOG = OUTPUT_DIR / "npm_detailed_log.txt"
SUMMARY_FILE = OUTPUT_DIR / "npm_summary.txt"
FAILURES_CSV = OUTPUT_DIR / "npm_failures.csv"
CHECKPOINT_FILE = OUTPUT_DIR / "checkpoint.json"
PROGRESS_FILE = OUTPUT_DIR / "progress.txt"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def ensure_dirs():
    """Create necessary directories."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

def get_all_zip_files():
    """Get all ZIP files in the NPM samples directory."""
    zips = []
    for root, _, files in os.walk(NPM_SAMPLES_DIR):
        for f in files:
            if f.endswith(".zip"):
                zips.append(Path(root) / f)
    return sorted(zips)

def load_checkpoint():
    """Load checkpoint to resume from last run."""
    if CHECKPOINT_FILE.exists():
        with open(CHECKPOINT_FILE, "r") as f:
            return json.load(f)
    return {"tested": [], "stats": {"BLOCKED": 0, "WARNING": 0, "SAFE": 0, "ERROR": 0, "TOTAL": 0}}

def save_checkpoint(checkpoint):
    """Save checkpoint for resumability."""
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump(checkpoint, f, indent=2)

def extract_zip(zip_path, dest_dir):
    """Extract a password-protected ZIP file."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(dest_dir, pwd=ZIP_PASSWORD)
        return True
    except Exception as e:
        return False

def clean_temp_dir():
    """Remove all extracted samples from temp directory."""
    if TEMP_EXTRACT_DIR.exists():
        shutil.rmtree(TEMP_EXTRACT_DIR)
    TEMP_EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

def get_package_name(zip_path):
    """Extract package name from ZIP filename."""
    return zip_path.stem  # filename without .zip

def scan_package(package_path):
    """
    Run the CI-Guard scanner on a package.
    Returns: (verdict, score, rules_triggered, scan_time, error)
    """
    start = time.time()
    
    try:
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "main_guard.py"), str(package_path)],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(PROJECT_ROOT)
        )
        
        duration = time.time() - start
        stdout = result.stdout
        stderr = result.stderr
        
        # Parse verdict
        if "Verdict: BLOCKED" in stdout:
            verdict = "BLOCKED"
        elif "Verdict: WARNING" in stdout:
            verdict = "WARNING"
        elif "Verdict: SAFE" in stdout:
            verdict = "SAFE"
        else:
            verdict = "ERROR"
        
        # Parse score
        score = 0
        for line in stdout.split("\n"):
            if "Static Risk Score:" in line:
                try:
                    score = int(line.split(":")[1].strip().split("/")[0])
                except:
                    pass
        
        # Get detailed rules by running scanner directly
        rules_detail = get_detailed_rules(package_path)
        
        return verdict, score, rules_detail, duration, None
        
    except subprocess.TimeoutExpired:
        return "TIMEOUT", 0, [], 60.0, "Scan timed out after 60s"
    except Exception as e:
        return "ERROR", 0, [], time.time() - start, str(e)

def get_detailed_rules(package_path):
    """Get detailed rule breakdown for a package."""
    rules_detail = []
    
    try:
        # Import scanner directly for detailed output
        sys.path.insert(0, str(PROJECT_ROOT))
        from analyzer.static_scanner import scan_directory
        
        report = scan_directory(str(package_path))
        
        for detail in report.get("details", []):
            file_path = detail.get("file", "unknown")
            file_name = os.path.basename(file_path)
            file_score = detail.get("score", 0)
            rules = detail.get("rules", [])
            
            rules_detail.append({
                "file": file_name,
                "score": file_score,
                "rules": rules
            })
        
        return rules_detail
        
    except Exception as e:
        return [{"file": "error", "score": 0, "rules": [str(e)]}]

def format_rules_for_log(rules_detail):
    """Format rules detail for the log file."""
    lines = []
    for item in rules_detail:
        lines.append(f"  📄 {item['file']} (Score: {item['score']})")
        for rule in item['rules']:
            # Parse rule ID and add description
            rule_desc = get_rule_description(rule)
            lines.append(f"      → {rule}: {rule_desc}")
    return "\n".join(lines) if lines else "  No rules triggered"

def get_rule_description(rule_id):
    """Get human-readable description for a rule."""
    descriptions = {
        "SA-001": "Shell Download (curl/wget piped to bash)",
        "SA-002": "Secret Exfiltration (env vars + network)",
        "SA-003": "Obfuscated Code (base64/eval)",
        "SA-004": "Process Spawning (exec/spawn/system)",
        "SA-005": "Binary Blob (exe/dll/so file)",
        "SA-006": "Typosquatting",
        "SA-007": "Dynamic Import",
        "SA-008": "Lifecycle Hook (preinstall/postinstall)",
        "SA-009": "Suspicious IP (hardcoded IP address)",
        "SA-010": "Sensitive Write (/etc/hosts, ~/.ssh, .npmrc)",
    }
    
    # Extract base rule ID
    base_id = rule_id.split()[0] if " " in rule_id else rule_id
    desc = descriptions.get(base_id, "Unknown rule")
    
    # Check for dead code marker
    if "(dead code)" in rule_id:
        desc += " (dead code)"
    
    return desc

def write_result_csv(package_name, verdict, score, duration, error, rules_detail):
    """Append a result to the CSV file (real-time save)."""
    # Create header if file doesn't exist
    if not RESULTS_CSV.exists():
        with open(RESULTS_CSV, "w") as f:
            f.write("id,package,verdict,score,duration,error,rules_summary\n")
    
    # Get current line count for ID
    with open(RESULTS_CSV, "r") as f:
        line_count = len(f.readlines())
    
    # Summarize rules
    rules_summary = "|".join([f"{r['file']}:{','.join(r['rules'])}" for r in rules_detail])
    rules_summary = rules_summary.replace('"', "'")[:500]  # Limit length
    
    # Append result
    with open(RESULTS_CSV, "a") as f:
        error_str = str(error).replace(",", ";") if error else ""
        f.write(f'{line_count},"{package_name}",{verdict},{score},{duration:.4f},"{error_str}","{rules_summary}"\n')

def write_detailed_log(package_name, verdict, score, duration, rules_detail, sample_num, total):
    """Append detailed log entry (real-time save)."""
    with open(DETAILED_LOG, "a") as f:
        f.write("\n" + "─" * 80 + "\n")
        f.write(f"[{sample_num}/{total}] NPM: {package_name}\n")
        f.write("─" * 80 + "\n")
        f.write(f"Verdict: {verdict}\n")
        f.write(f"Score: {score}/100\n")
        f.write(f"Scan Time: {duration:.3f}s\n")
        f.write(f"\nRules Triggered:\n")
        f.write(format_rules_for_log(rules_detail) + "\n")

def write_failure(package_name, verdict, score, rules_detail):
    """Record packages that were NOT blocked (for investigation)."""
    if not FAILURES_CSV.exists():
        with open(FAILURES_CSV, "w") as f:
            f.write("package,verdict,score,rules\n")
    
    if verdict not in ["BLOCKED", "TIMEOUT"]:
        rules_str = "|".join([",".join(r['rules']) for r in rules_detail])
        with open(FAILURES_CSV, "a") as f:
            f.write(f'"{package_name}",{verdict},{score},"{rules_str}"\n')

def update_progress(current, total, stats, start_time):
    """Update progress file."""
    elapsed = time.time() - start_time
    rate = current / elapsed if elapsed > 0 else 0
    remaining = (total - current) / rate if rate > 0 else 0
    
    tpr = (stats["BLOCKED"] / stats["TOTAL"] * 100) if stats["TOTAL"] > 0 else 0
    
    with open(PROGRESS_FILE, "w") as f:
        f.write(f"CI-Guard NPM Batch Test - Progress\n")
        f.write(f"=" * 50 + "\n")
        f.write(f"Started: {datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Current: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"\nProgress: {current}/{total} ({current/total*100:.1f}%)\n")
        f.write(f"Rate: {rate:.1f} samples/sec\n")
        f.write(f"ETA: {remaining/60:.1f} minutes\n")
        f.write(f"\nCurrent Stats:\n")
        f.write(f"  BLOCKED: {stats['BLOCKED']} ({stats['BLOCKED']/stats['TOTAL']*100:.1f}%)\n" if stats['TOTAL'] > 0 else "  BLOCKED: 0\n")
        f.write(f"  WARNING: {stats['WARNING']}\n")
        f.write(f"  SAFE: {stats['SAFE']}\n")
        f.write(f"  ERROR: {stats['ERROR']}\n")
        f.write(f"\nDetection Rate (TPR): {tpr:.1f}%\n")

def write_final_summary(stats, total_time):
    """Write final summary file."""
    tpr = (stats["BLOCKED"] / stats["TOTAL"] * 100) if stats["TOTAL"] > 0 else 0
    
    with open(SUMMARY_FILE, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("CI SUPPLY CHAIN GUARD - NPM BATCH TEST SUMMARY\n")
        f.write("=" * 60 + "\n")
        f.write(f"Test Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Duration: {total_time/60:.1f} minutes\n")
        f.write(f"\n" + "-" * 60 + "\n")
        f.write("RESULTS\n")
        f.write("-" * 60 + "\n")
        f.write(f"Total Samples Tested: {stats['TOTAL']}\n\n")
        f.write(f"  🔴 BLOCKED:  {stats['BLOCKED']:>6} ({stats['BLOCKED']/stats['TOTAL']*100:.1f}%)\n" if stats['TOTAL'] > 0 else "")
        f.write(f"  🟡 WARNING:  {stats['WARNING']:>6} ({stats['WARNING']/stats['TOTAL']*100:.1f}%)\n" if stats['TOTAL'] > 0 else "")
        f.write(f"  🟢 SAFE:     {stats['SAFE']:>6} ({stats['SAFE']/stats['TOTAL']*100:.1f}%)\n" if stats['TOTAL'] > 0 else "")
        f.write(f"  ⚠️  ERROR:    {stats['ERROR']:>6} ({stats['ERROR']/stats['TOTAL']*100:.1f}%)\n" if stats['TOTAL'] > 0 else "")
        f.write(f"\n" + "-" * 60 + "\n")
        f.write("DETECTION METRICS\n")
        f.write("-" * 60 + "\n")
        f.write(f"True Positive Rate (TPR): {tpr:.2f}%\n")
        f.write(f"  (BLOCKED / TOTAL)\n\n")
        f.write(f"Samples NOT Blocked: {stats['WARNING'] + stats['SAFE']}\n")
        f.write(f"  (See npm_failures.csv for investigation)\n")
        f.write(f"\n" + "-" * 60 + "\n")
        f.write("PERFORMANCE\n")
        f.write("-" * 60 + "\n")
        f.write(f"Average Scan Time: {total_time/stats['TOTAL']:.3f}s per sample\n" if stats['TOTAL'] > 0 else "")
        f.write(f"Total Runtime: {total_time:.1f}s ({total_time/60:.1f} min)\n")
        f.write(f"\n" + "=" * 60 + "\n")

# ============================================================================
# MAIN BATCH PROCESSING
# ============================================================================

def process_batch(zip_files, checkpoint, batch_num, total_batches, global_start, total_samples):
    """Process a batch of ZIP files."""
    batch_start = time.time()
    
    print(f"\n{'='*60}")
    print(f"BATCH {batch_num}/{total_batches} ({len(zip_files)} samples)")
    print(f"{'='*60}")
    
    # Extract all ZIPs in this batch
    print(f"[1/3] Extracting {len(zip_files)} samples...")
    extracted = []
    for zf in zip_files:
        pkg_name = get_package_name(zf)
        dest = TEMP_EXTRACT_DIR / pkg_name
        if extract_zip(zf, dest):
            extracted.append((pkg_name, dest))
        else:
            # Log extraction failure
            write_result_csv(pkg_name, "ERROR", 0, 0, "Extraction failed", [])
            checkpoint["stats"]["ERROR"] += 1
            checkpoint["stats"]["TOTAL"] += 1
            checkpoint["tested"].append(str(zf))
    
    print(f"    Extracted: {len(extracted)}/{len(zip_files)}")
    
    # Scan each extracted package
    print(f"[2/3] Scanning packages...")
    for i, (pkg_name, pkg_path) in enumerate(extracted):
        # Find the actual package directory (might be nested)
        actual_path = pkg_path
        subdirs = list(pkg_path.iterdir()) if pkg_path.exists() else []
        if len(subdirs) == 1 and subdirs[0].is_dir():
            actual_path = subdirs[0]
        
        # Scan
        verdict, score, rules_detail, duration, error = scan_package(actual_path)
        
        # Update stats
        checkpoint["stats"]["TOTAL"] += 1
        if verdict in checkpoint["stats"]:
            checkpoint["stats"][verdict] += 1
        else:
            checkpoint["stats"]["ERROR"] += 1
        
        # Save results (real-time)
        sample_num = checkpoint["stats"]["TOTAL"]
        write_result_csv(pkg_name, verdict, score, duration, error, rules_detail)
        write_detailed_log(pkg_name, verdict, score, duration, rules_detail, sample_num, total_samples)
        write_failure(pkg_name, verdict, score, rules_detail)
        
        # Mark as tested
        checkpoint["tested"].append(pkg_name)
        
        # Progress indicator
        if (i + 1) % 50 == 0 or i == len(extracted) - 1:
            pct = (i + 1) / len(extracted) * 100
            print(f"    Scanned: {i+1}/{len(extracted)} ({pct:.0f}%)")
            save_checkpoint(checkpoint)
            update_progress(checkpoint["stats"]["TOTAL"], total_samples, checkpoint["stats"], global_start)
    
    # Clean up extracted files
    print(f"[3/3] Cleaning up extracted files...")
    clean_temp_dir()
    
    batch_time = time.time() - batch_start
    print(f"    Batch completed in {batch_time:.1f}s")
    
    # Save checkpoint after batch
    save_checkpoint(checkpoint)
    
    return checkpoint

def main():
    parser = argparse.ArgumentParser(description="CI-Guard NPM Batch Tester")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                        help=f"Number of samples per batch (default: {DEFAULT_BATCH_SIZE})")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from last checkpoint")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit total samples to test (0 = all)")
    args = parser.parse_args()
    
    # Setup
    ensure_dirs()
    clean_temp_dir()
    
    # Initialize log file header
    if not args.resume or not DETAILED_LOG.exists():
        with open(DETAILED_LOG, "w") as f:
            f.write("=" * 80 + "\n")
            f.write("CI SUPPLY CHAIN GUARD - NPM DETAILED TEST RESULTS\n")
            f.write("=" * 80 + "\n")
            f.write(f"Test Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Batch Size: {args.batch_size}\n")
            f.write("=" * 80 + "\n")
    
    # Get all ZIP files
    print("Scanning for NPM malware samples...")
    all_zips = get_all_zip_files()
    print(f"Found {len(all_zips)} ZIP files")
    
    if args.limit > 0:
        all_zips = all_zips[:args.limit]
        print(f"Limited to {args.limit} samples")
    
    # Load checkpoint for resuming
    if args.resume:
        checkpoint = load_checkpoint()
        tested_set = set(checkpoint["tested"])
        all_zips = [z for z in all_zips if get_package_name(z) not in tested_set]
        print(f"Resuming: {len(checkpoint['tested'])} already tested, {len(all_zips)} remaining")
    else:
        checkpoint = {"tested": [], "stats": {"BLOCKED": 0, "WARNING": 0, "SAFE": 0, "ERROR": 0, "TOTAL": 0}}
        # Clear previous results
        for f in [RESULTS_CSV, FAILURES_CSV]:
            if f.exists():
                f.unlink()
    
    if not all_zips:
        print("No samples to test!")
        return
    
    total_samples = len(all_zips) + checkpoint["stats"]["TOTAL"]
    
    # Split into batches
    batches = [all_zips[i:i+args.batch_size] for i in range(0, len(all_zips), args.batch_size)]
    total_batches = len(batches)
    
    print(f"\nTest Configuration:")
    print(f"  Total Samples: {total_samples}")
    print(f"  Batch Size: {args.batch_size}")
    print(f"  Number of Batches: {total_batches}")
    print(f"  Output Directory: {OUTPUT_DIR}")
    
    # Estimate time
    est_time = total_samples * 0.1  # ~0.1s per sample
    print(f"  Estimated Time: {est_time/60:.1f} minutes")
    
    print("\n" + "=" * 60)
    print("STARTING BATCH TEST")
    print("=" * 60)
    print("Press Ctrl+C to stop (progress is saved)")
    
    global_start = time.time()
    
    try:
        for batch_num, batch in enumerate(batches, 1):
            checkpoint = process_batch(
                batch, checkpoint, batch_num, total_batches, 
                global_start, total_samples
            )
            
            # Print running stats
            stats = checkpoint["stats"]
            if stats["TOTAL"] > 0:
                tpr = stats["BLOCKED"] / stats["TOTAL"] * 100
                print(f"\n📊 Running Stats: BLOCKED={stats['BLOCKED']} ({tpr:.1f}%), "
                      f"WARNING={stats['WARNING']}, SAFE={stats['SAFE']}, ERROR={stats['ERROR']}")
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user!")
        print(f"Progress saved. Run with --resume to continue.")
        save_checkpoint(checkpoint)
    
    # Final summary
    total_time = time.time() - global_start
    write_final_summary(checkpoint["stats"], total_time)
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)
    
    stats = checkpoint["stats"]
    if stats["TOTAL"] > 0:
        tpr = stats["BLOCKED"] / stats["TOTAL"] * 100
        print(f"\n📊 FINAL RESULTS:")
        print(f"   Total Tested: {stats['TOTAL']}")
        print(f"   🔴 BLOCKED:   {stats['BLOCKED']} ({tpr:.1f}%)")
        print(f"   🟡 WARNING:   {stats['WARNING']}")
        print(f"   🟢 SAFE:      {stats['SAFE']}")
        print(f"   ⚠️  ERROR:     {stats['ERROR']}")
        print(f"\n   Detection Rate (TPR): {tpr:.2f}%")
        print(f"   Total Time: {total_time/60:.1f} minutes")
    
    print(f"\n📁 Output Files:")
    print(f"   {RESULTS_CSV}")
    print(f"   {DETAILED_LOG}")
    print(f"   {SUMMARY_FILE}")
    print(f"   {FAILURES_CSV}")

if __name__ == "__main__":
    main()

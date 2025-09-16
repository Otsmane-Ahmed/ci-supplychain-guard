#!/usr/bin/env python3

import os
import sys
import csv
import json
import time
import shutil
import zipfile
import subprocess
from datetime import datetime
from pathlib import Path

DATASET_BASE = "../dataset/private_raw/datadog_malware/samples/pypi"
OUTPUT_DIR = "pypi_results"
TEMP_DIR = "temp_extracted"
BATCH_SIZE = 50
ZIP_PASSWORD = "infected"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from analyzer.static_scanner import scan_directory

def find_all_samples():
    samples = []
    base = Path(DATASET_BASE)
    
    if not base.exists():
        print(f"Dataset not found: {DATASET_BASE}")
        return samples
    
    for zip_file in base.rglob("*.zip"):
        samples.append(str(zip_file))
    
    return sorted(samples)

def extract_sample(zip_path, extract_to):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_to, pwd=ZIP_PASSWORD.encode())
        return True
    except Exception as e:
        return False

def scan_sample(sample_dir):
    try:
        report = scan_directory(sample_dir)
        score = report['total_score']
        
        rules = []
        for detail in report.get('details', []):
            file_name = os.path.basename(detail['file'])
            for rule in detail['rules']:
                rules.append(f"{file_name}:{rule}")
        
        if score <= 3:
            verdict = "SAFE"
        elif score >= 10:
            verdict = "BLOCKED"
        else:
            verdict = "WARNING"
        
        return verdict, score, rules
    except Exception as e:
        return "ERROR", 0, [str(e)]

def load_checkpoint():
    checkpoint_file = os.path.join(OUTPUT_DIR, "checkpoint.json")
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, 'r') as f:
            return json.load(f)
    return {"processed": 0, "last_sample": ""}

def save_checkpoint(processed, last_sample):
    checkpoint_file = os.path.join(OUTPUT_DIR, "checkpoint.json")
    with open(checkpoint_file, 'w') as f:
        json.dump({"processed": processed, "last_sample": last_sample}, f)

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)
    
    samples = find_all_samples()
    total = len(samples)
    
    if total == 0:
        print("No samples found!")
        return
    
    print(f"Found {total} PyPI samples")
    
    checkpoint = load_checkpoint()
    start_idx = checkpoint["processed"]
    
    if start_idx > 0:
        print(f"Resuming from sample {start_idx}")
    
    results_file = os.path.join(OUTPUT_DIR, "pypi_full_results.csv")
    log_file = os.path.join(OUTPUT_DIR, "pypi_detailed_log.txt")
    
    file_mode = 'a' if start_idx > 0 else 'w'
    
    csv_file = open(results_file, file_mode, newline='')
    csv_writer = csv.writer(csv_file)
    
    if start_idx == 0:
        csv_writer.writerow(['id', 'package', 'verdict', 'score', 'duration', 'error', 'rules_summary'])
    
    log = open(log_file, file_mode)
    
    stats = {"BLOCKED": 0, "WARNING": 0, "SAFE": 0, "ERROR": 0}
    start_time = time.time()
    
    try:
        for idx in range(start_idx, total):
            sample_path = samples[idx]
            sample_name = os.path.basename(sample_path).replace('.zip', '')
            
            sample_start = time.time()
            
            extract_dir = os.path.join(TEMP_DIR, f"sample_{idx}")
            os.makedirs(extract_dir, exist_ok=True)
            
            if not extract_sample(sample_path, extract_dir):
                verdict, score, rules = "ERROR", 0, ["extraction_failed"]
                error_msg = "extraction_failed"
            else:
                verdict, score, rules = scan_sample(extract_dir)
                error_msg = ""
            
            duration = time.time() - sample_start
            
            stats[verdict] = stats.get(verdict, 0) + 1
            
            rules_str = "|".join(rules[:10])
            csv_writer.writerow([idx + 1, sample_name, verdict, score, f"{duration:.4f}", error_msg, rules_str])
            csv_file.flush()
            
            log.write(f"[{idx + 1}/{total}] {sample_name}: {verdict} (score={score}, time={duration:.2f}s)\n")
            log.flush()
            
            shutil.rmtree(extract_dir, ignore_errors=True)
            
            if (idx + 1) % 10 == 0:
                elapsed = time.time() - start_time
                rate = (idx + 1 - start_idx) / elapsed if elapsed > 0 else 0
                eta = (total - idx - 1) / rate / 60 if rate > 0 else 0
                
                print(f"[{idx + 1}/{total}] BLOCKED:{stats['BLOCKED']} WARNING:{stats['WARNING']} "
                      f"SAFE:{stats['SAFE']} ERROR:{stats['ERROR']} | ETA: {eta:.1f}min")
            
            if (idx + 1) % BATCH_SIZE == 0:
                save_checkpoint(idx + 1, sample_name)
                shutil.rmtree(TEMP_DIR, ignore_errors=True)
                os.makedirs(TEMP_DIR, exist_ok=True)
    
    except KeyboardInterrupt:
        print("\nInterrupted! Saving checkpoint...")
        save_checkpoint(idx, sample_name)
    
    finally:
        csv_file.close()
        log.close()
        shutil.rmtree(TEMP_DIR, ignore_errors=True)
    
    total_time = time.time() - start_time
    
    summary = f"""
{'='*60}
CI SUPPLY CHAIN GUARD - PyPI BATCH TEST SUMMARY
{'='*60}
Test Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Duration: {total_time/60:.1f} minutes

{'='*60}
RESULTS
{'='*60}
Total Samples Tested: {total}

   BLOCKED:   {stats['BLOCKED']} ({100*stats['BLOCKED']/total:.1f}%)
   WARNING:   {stats['WARNING']} ({100*stats['WARNING']/total:.1f}%)
   SAFE:      {stats['SAFE']} ({100*stats['SAFE']/total:.1f}%)
   ERROR:     {stats['ERROR']} ({100*stats['ERROR']/total:.1f}%)

Detection Rate: {100*(stats['BLOCKED']+stats['WARNING'])/total:.1f}%
{'='*60}
"""
    
    print(summary)
    
    with open(os.path.join(OUTPUT_DIR, "pypi_summary.txt"), 'w') as f:
        f.write(summary)
    
    with open(os.path.join(OUTPUT_DIR, "pypi_failures.csv"), 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['id', 'package', 'verdict', 'score', 'rules'])
        
        with open(results_file, 'r') as rf:
            reader = csv.DictReader(rf)
            for row in reader:
                if row['verdict'] in ['SAFE', 'WARNING', 'ERROR']:
                    writer.writerow([row['id'], row['package'], row['verdict'], row['score'], row['rules_summary']])

if __name__ == "__main__":
    main()

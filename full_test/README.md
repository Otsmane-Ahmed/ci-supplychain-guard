# Full Test Suite

This directory contains automation scripts for comprehensive testing of the CI Supply Chain Guard tool against all available malware samples.

## Scripts

### 1. `run_quick_test.py`
**Purpose:** Fast validation test using only pre-extracted samples.
**Runtime:** ~10 seconds
**Samples:** 24 (20 real malware + 1 simulated + 1 historical + 1 dead code + 1 benign)

```bash
python full_test/run_quick_test.py
```

### 2. `run_batch_test.py`
**Purpose:** Full test against the entire Datadog malware dataset (17,000+ samples).
**Runtime:** Several hours (depending on sample count)
**Features:**
- Progress checkpointing (can be stopped and resumed)
- Batch saving every 100 samples
- Supports `--limit` for partial runs

```bash
# Run all samples (may take hours)
python full_test/run_batch_test.py

# Run first 500 samples only
python full_test/run_batch_test.py --limit 500

# Resume from where you left off
python full_test/run_batch_test.py --resume
```

### 3. `run_full_test.py`
**Purpose:** Complete test of ALL samples (extracted + zipped Datadog).
**Runtime:** Very long
**Note:** Use `run_batch_test.py` for better control.

## Output Files

| File | Description |
|------|-------------|
| `quick_test_results.csv` | Results from quick test (24 samples) |
| `datadog_results.csv` | Results from batch test (Datadog samples) |
| `datadog_summary.txt` | Summary statistics for Datadog test |
| `checkpoint.json` | Progress checkpoint for resumable batch test |
| `results.csv` | Full results (if run_full_test.py completes) |
| `failures.csv` | Samples that weren't blocked (need investigation) |
| `detailed_log.txt` | Verbose output from each scan |
| `summary.txt` | Human-readable summary |

## CSV Schema

```csv
id,ecosystem,package,verdict,score,duration,error
1,npm,malicious-package,BLOCKED,17,0.045,
2,pypi,evil-lib,SAFE,3,0.052,
```

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `BLOCKED` | Detected as malicious (Score ≥ 10) |
| `WARNING` | Suspicious, needs sandbox (Score 4-9) |
| `SAFE` | No threats detected (Score ≤ 3) |
| `ERROR` | Extraction or scan failed |
| `TIMEOUT` | Scan exceeded 30s limit |

## Metrics

- **TPR (True Positive Rate):** % of malware correctly detected
- **FPR (False Positive Rate):** % of benign code incorrectly flagged

## Usage for Research

1. Run quick test first to validate tool is working:
   ```bash
   python full_test/run_quick_test.py
   ```

2. Run batch test with a limit to estimate full runtime:
   ```bash
   python full_test/run_batch_test.py --limit 100
   ```

3. Run full batch test (can be stopped with Ctrl+C and resumed):
   ```bash
   python full_test/run_batch_test.py
   # If interrupted:
   python full_test/run_batch_test.py --resume
   ```

4. Analyze results in CSV files using Excel, Python/Pandas, or any data tool.

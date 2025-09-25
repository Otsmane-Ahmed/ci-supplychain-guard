# Full Test Suite

This directory contains the evaluation results and automation scripts for testing CI-Guard against real-world malware datasets.

## Directory Structure

```
full_test/
├── EVALUATION_REPORT.md      # Detailed evaluation report with methodology and results
├── README.md                 # This file
├── npm/                      # NPM ecosystem evaluation
│   ├── run_npm_batch_test.py
│   ├── analyze_results_by_category.py
│   ├── npm_results/          # Final results (89.6% detection)
│   └── npm_results_old_45pct/# Initial results before optimization (45.1% detection)
└── pypi/                     # PyPI ecosystem evaluation
    ├── run_pypi_batch_test.py
    └── pypi_results/         # Results (pending)
```

## Evaluation Summary

### NPM Dataset
- **Total Samples:** 15,059
- **Initial Detection Rate:** 45.1% (before rule optimization)
- **Final Detection Rate:** 89.6% (after rule optimization)
- **Runtime:** ~8.5 hours

### PyPI Dataset
- **Total Samples:** 2,257
- **Test Completed:** 2025-12-14 14:32 (Duration: 17.3 minutes)
- **Results:**
   - BLOCKED: 265 (11.7%)
   - WARNING: 1,067 (47.3%)
   - SAFE: 923 (40.9%)
   - ERROR: 0 (0.0%)
- **Detection Rate:** 59.0%

## Scripts

### NPM Testing: `npm/run_npm_batch_test.py`
**Purpose:** Test against the full Datadog NPM malware dataset.
**Features:**
- Progress checkpointing (can be stopped and resumed)
- Batch saving every 100 samples
- Supports `--limit` and `--resume` flags

```bash
cd full_test/npm
python run_npm_batch_test.py --limit 500  # Test first 500 samples
python run_npm_batch_test.py --resume     # Resume from checkpoint
```

### PyPI Testing: `pypi/run_pypi_batch_test.py`
**Purpose:** Test against the full Datadog PyPI malware dataset.
**Features:** Same as NPM script.

```bash
cd full_test/pypi
python run_pypi_batch_test.py
```

### Analysis: `npm/analyze_results_by_category.py`
**Purpose:** Categorize results by attack type and analyze detection patterns.

```bash
python npm/analyze_results_by_category.py
```

## Output Files

Each ecosystem folder (npm/, pypi/) contains:

| File | Description |
|------|-------------|
| `*_results/datadog_results.csv` | Full results for all samples |
| `*_results/datadog_summary.txt` | Summary statistics |
| `*_results/failures.csv` | Samples marked SAFE (false negatives) |
| `checkpoint.json` | Progress checkpoint for resumable runs |

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

1. Run NPM batch test:
   ```bash
   cd full_test/npm
   python run_npm_batch_test.py --limit 100  # Test first
   python run_npm_batch_test.py              # Full run
   ```

2. Run PyPI batch test:
   ```bash
   cd full_test/pypi
   python run_pypi_batch_test.py
   ```

3. Analyze results in CSV files using Excel, Python/Pandas, or any data tool.

4. See `EVALUATION_REPORT.md` for detailed methodology and findings.

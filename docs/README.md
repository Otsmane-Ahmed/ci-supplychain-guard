# Documentation & Research

This directory contains the academic and administrative output of the CI-Guard research project. It bridges the gap between the technical implementation and the scientific contribution required for publication.

## Files

### 1. PAPER_OUTLINE.md
**Type:** Manuscript Draft
**Function:**
* Outlines the structural skeleton for the IEEE/arXiv submission.
* Defines the key sections: Abstract, Introduction, Threat Model, Methodology (AST + Sandbox), Evaluation (Benchmark Results), and Conclusion.
* Serves as the roadmap for translating engineering logs into academic prose.

### 2. EVALUATION_PLAN.md
**Type:** Experimental Design
**Function:**
* Formally defines the three core Research Questions (RQs):
    1.  **Detection Efficacy:** Can we detect known patterns?
    2.  **Evasion Resistance:** Can we catch obfuscated/stalling malware?
    3.  **Operational Viability:** Is the runtime overhead acceptable?
* Specifies the dataset partitioning (70% training, 15% validation, 15% testing).
* Lists the quantitative metrics for success (e.g., True Positive Rate, False Positive Rate).

### 3. EXECUTIVE_SUMMARY_ONE_PAGE.md
**Type:** Project Brief
**Function:**
* A high-level summary of the research tailored for stakeholders, recruiters, or scholarship committees.
* concise highlights of key innovations (Active Deception, Reachability Analysis).
* summarizes quantitative results (e.g., "100% TPR on simulated attacks," "0.34s latency").

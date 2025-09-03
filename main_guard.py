import sys
import os
import argparse

# Allow imports from subdirectories
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from analyzer.static_scanner import scan_directory
from sandbox.sandbox_runner import build_sandbox, run_sample

def main():
    parser = argparse.ArgumentParser(description="CI Supply Chain Guard")
    parser.add_argument("target", help="Directory to scan")
    args = parser.parse_args()

    target_dir = args.target
    print(f"Scanning target: {target_dir}")
    
    # 1. Static Analysis
    print("Running static analysis...")
    static_report = scan_directory(target_dir)
    score = static_report['total_score']
    print(f"Static Risk Score: {score}/100")
    
    # 2. Decision Logic
    if score <= 3:
        print("Verdict: SAFE")
        sys.exit(0)
        
    elif score >= 10:
        print("Verdict: BLOCKED (Critical Risk)")
        sys.exit(1)
        
    else:
        # Score 4-9
        print(f"Verdict: SUSPICIOUS (Score {score}). Initiating sandbox...")
        
        build_sandbox()
        verdict, evidence = run_sample(target_dir)
        
        if verdict == "MALICIOUS":
            print("Verdict: BLOCKED (Sandbox Confirmed)")
            for e in evidence:
                print(f"  - {e}")
            sys.exit(1)
        else:
            print("Verdict: WARNING (Manual Review Required)")
            sys.exit(0)

if __name__ == "__main__":
    main()

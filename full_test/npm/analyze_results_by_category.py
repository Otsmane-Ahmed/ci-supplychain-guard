#!/usr/bin/env python3

import csv
import os

def analyze_results():
    results_file = "npm_results/npm_full_results.csv"
    
    if not os.path.exists(results_file):
        print(f"Results file not found: {results_file}")
        return
    
    categories = {
        'compromised_lib': {'total': 0, 'blocked': 0, 'warning': 0, 'safe': 0, 'other': 0},
        'malicious_intent': {'total': 0, 'blocked': 0, 'warning': 0, 'safe': 0, 'other': 0},
        'unknown': {'total': 0, 'blocked': 0, 'warning': 0, 'safe': 0, 'other': 0}
    }
    
    with open(results_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            sample = row.get('sample', '')
            verdict = row.get('verdict', '').upper()
            
            if 'malicious_intent' in sample:
                cat = 'malicious_intent'
            elif 'compromised_lib' in sample:
                cat = 'compromised_lib'
            else:
                cat = 'unknown'
            
            categories[cat]['total'] += 1
            
            if verdict == 'BLOCKED':
                categories[cat]['blocked'] += 1
            elif verdict == 'WARNING':
                categories[cat]['warning'] += 1
            elif verdict == 'SAFE':
                categories[cat]['safe'] += 1
            else:
                categories[cat]['other'] += 1
    
    print("=" * 70)
    print("DETECTION RATE BY CATEGORY")
    print("=" * 70)
    
    for cat, data in categories.items():
        if data['total'] == 0:
            continue
            
        total = data['total']
        detected = data['blocked'] + data['warning']
        
        print(f"\n{cat.upper()}")
        print("-" * 40)
        print(f"Total: {total}")
        print(f"  BLOCKED: {data['blocked']} ({100*data['blocked']/total:.1f}%)")
        print(f"  WARNING: {data['warning']} ({100*data['warning']/total:.1f}%)")
        print(f"  SAFE:    {data['safe']} ({100*data['safe']/total:.1f}%)")
        print(f"  OTHER:   {data['other']} ({100*data['other']/total:.1f}%)")
        print(f"Detection rate: {100*detected/total:.1f}%")

if __name__ == "__main__":
    analyze_results()

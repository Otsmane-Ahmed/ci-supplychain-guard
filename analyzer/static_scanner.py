import os
import re
import sys

try:
    from analyzer.ast_utils import analyze_reachability
except ImportError:
    from ast_utils import analyze_reachability

RULES = [
    {"id": "SA-001", "name": "Shell Download", "pattern": r"(curl|wget|fetch).{0,50}\|\s*(sh|bash)", "weight": 10},
    {"id": "SA-002", "name": "Secret Exfiltration", "pattern": r"process\.env.*(https?\.get|axios|fetch|net\.connect)", "weight": 10},
    {"id": "SA-003", "name": "Obfuscated Code", "pattern": r"(Buffer\.from\(.*base64|eval\(.*atob)", "weight": 8},
    {"id": "SA-004", "name": "Process Spawning", "pattern": r"(child_process\.exec|spawn|os\.system|subprocess\.call)", "weight": 7},
    {"id": "SA-005", "name": "Binary Blob", "pattern": r"\.(exe|dll|node|so)$", "weight": 6, "scope": "ext"},
    {"id": "SA-007", "name": "Dynamic Import", "pattern": r"(require|import)\(.*$\{", "weight": 5},
    {"id": "SA-008", "name": "Lifecycle Hook", "pattern": r"(preinstall|postinstall)", "weight": 3, "scope": "name"},
    {"id": "SA-009", "name": "Suspicious IP", "pattern": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "weight": 7},
    {"id": "SA-010", "name": "Sensitive Write", "pattern": r"(/etc/hosts|~/\.ssh|\.npmrc)", "weight": 9},
]

def scan_file(filepath):
    hits = []
    score = 0
    
    try:
        filename = os.path.basename(filepath)
        
        # Metadata checks
        for rule in RULES:
            if rule.get("scope") == "ext" and re.search(rule["pattern"], filename):
                hits.append(rule["id"])
                score += rule["weight"]
            elif rule.get("scope") == "name" and filename == "package.json":
                pass 

        # Content checks
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
            
            if filename == "package.json":
                if "preinstall" in content or "postinstall" in content:
                     hits.append("SA-008")
                     score += 3

            for rule in RULES:
                if rule.get("scope"): continue
                
                if re.search(rule["pattern"], content, re.IGNORECASE | re.DOTALL):
                    if rule["id"] in hits: continue

                    # AST reachability check
                    is_reachable = analyze_reachability(filepath, rule["id"], rule["pattern"])
                    
                    weight = rule["weight"]
                    note = ""
                    
                    if not is_reachable:
                        weight = int(weight / 2)
                        note = "(dead code)"
                    
                    hits.append(f"{rule['id']} {note}".strip())
                    score += weight
                        
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        
    return score, hits

def scan_directory(target_dir):
    report = {"target": target_dir, "total_score": 0, "details": []}
    
    for root, _, files in os.walk(target_dir):
        for file in files:
            filepath = os.path.join(root, file)
            score, hits = scan_file(filepath)
            
            if score > 0:
                report["total_score"] += score
                report["details"].append({"file": filepath, "score": score, "rules": hits})
                print(f"  Detected: {file} | Score: {score} | Rules: {hits}")

    return report

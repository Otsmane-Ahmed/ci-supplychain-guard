import os
import re
import sys

try:
    from analyzer.ast_utils import analyze_reachability
except ImportError:
    from ast_utils import analyze_reachability

RULES = [
    {"id": "SA-001", "name": "Shell Download", "pattern": r"(curl|wget|fetch).{0,50}\|\s*(sh|bash)", "weight": 10},
    {"id": "SA-002", "name": "Secret Exfiltration", "pattern": r"(os\.userInfo|os\.hostname|process\.env).{0,100}(https|http|dns|net\.connect|fetch|axios)", "weight": 8},
    {"id": "SA-003", "name": "Obfuscated Code", "pattern": r"(Buffer\.from\(.*base64|eval\(.*atob|atob\(|btoa\()", "weight": 8},
    {"id": "SA-004", "name": "Process Spawning", "pattern": r"(child_process|\.exec\(|\.spawn\(|os\.system|subprocess|\.popen)", "weight": 7},
    {"id": "SA-005", "name": "Binary Blob", "pattern": r"\.(exe|dll|node|so)$", "weight": 6, "scope": "ext"},
    {"id": "SA-006", "name": "DNS Exfiltration", "pattern": r"dns\.(resolve|lookup).{0,50}(userInfo|hostname|username)", "weight": 9},
    {"id": "SA-007", "name": "Dynamic Import", "pattern": r"(require|import)\(.*\$\{", "weight": 5},
    {"id": "SA-008", "name": "Lifecycle Hook", "pattern": r"(preinstall|postinstall)", "weight": 5, "scope": "name"},
    {"id": "SA-009", "name": "Suspicious Domain", "pattern": r"(oastify\.com|burpcollaborator|interact\.sh|requestbin|pipedream)", "weight": 10},
    {"id": "SA-010", "name": "Sensitive Write", "pattern": r"(\/etc\/|\.ssh|\.bashrc|\.npmrc|\.aws)", "weight": 9},
    {"id": "SA-013", "name": "Python Exec", "pattern": r"\bexec\s*\(|\beval\s*\(|\bcompile\s*\(", "weight": 8},
    {"id": "SA-014", "name": "Python Dynamic Import", "pattern": r"__import__\s*\(", "weight": 6},
    {"id": "SA-015", "name": "Python Env Access", "pattern": r"os\.environ|os\.getenv", "weight": 4},
    {"id": "SA-016", "name": "Python Socket", "pattern": r"socket\.socket\s*\(", "weight": 7},
    {"id": "SA-017", "name": "Python Base64", "pattern": r"base64\.(b64decode|decodebytes)", "weight": 5},
]

DANGEROUS_LIFECYCLE_PATTERN = re.compile(
    r'"(preinstall|postinstall)"\s*:\s*"[^"]*\b(curl|wget|bash|sh|node\s+-e|python|nc|eval)\b',
    re.IGNORECASE
)

# New: Detect setup.py with dangerous install commands
DANGEROUS_SETUP_PATTERN = re.compile(
    r"(cmdclass|install_requires|setup\s*\().{0,500}(exec|eval|subprocess|os\.system|__import__|requests\.get|urllib)",
    re.IGNORECASE | re.DOTALL
)

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
            elif rule.get("scope") == "name" and filename == "setup.py":
                # setup.py is always interesting
                pass

        # Content checks
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
            
            if filename == "package.json":
                if "preinstall" in content or "postinstall" in content:
                    hits.append("SA-008")
                    score += 5
                    
                    if DANGEROUS_LIFECYCLE_PATTERN.search(content):
                        hits.append("SA-011")
                        score += 8
            
            # New: Smart checks for setup.py
            if filename == "setup.py":
                if DANGEROUS_SETUP_PATTERN.search(content):
                    hits.append("SA-011") # Reuse ID for dangerous install
                    score += 8

            for rule in RULES:
                if rule.get("scope"): continue
                
                if re.search(rule["pattern"], content, re.IGNORECASE | re.DOTALL):
                    if rule["id"] in hits: continue

                    # AST reachability check
                    is_reachable = analyze_reachability(filepath, rule["id"], rule["pattern"])
                    
                    weight = rule["weight"]
                    note = ""
                    
                    if not is_reachable:
                        # FIX: Dead code is now worth only 1 point (Noise Reduction)
                        weight = 1
                        note = "(dead code)"
                    else:
                        # New: Increase weight for critical Python files (setup.py, __init__.py)
                        # If a rule like Process Spawning (SA-004) is found in setup.py, it's very suspicious
                        if filename in ["setup.py", "__init__.py"] and rule["id"] in ["SA-004", "SA-013"]:
                            weight = 10  # Auto-BLOCK weight similar to SA-001
                    
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
                # Only print distinct hits to reduce noise
                # print(f"  Detected: {file} | Score: {score} | Rules: {hits}")

    return report

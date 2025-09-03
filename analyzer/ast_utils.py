import re

def is_reachable_js(content, pattern):
    """
    Returns True if pattern exists outside of standard JS comments.
    """
    # Strip single-line comments
    clean_content = re.sub(r"//.*", "", content)
    
    # Strip multi-line comments
    clean_content = re.sub(r"/\*[\s\S]*?\*/", "", clean_content)
    
    if re.search(pattern, clean_content, re.DOTALL):
        return True
    
    return False

def analyze_reachability(filepath, rule_id, pattern):
    """
    Determines if a rule hit is strictly reachable (e.g., not commented out).
    Defaults to True for non-JS files to be safe.
    """
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
            
        if filepath.endswith((".js", ".ts")):
            return is_reachable_js(content, pattern)
            
        return True
        
    except Exception:
        # If read fails, assume unsafe to avoid false negatives
        return True

import requests
import os
import subprocess
import time
import json
from concurrent.futures import ThreadPoolExecutor

# Configuration
TOP_N = 1000
OUTPUT_DIR = "dataset/sanitized_samples/benign_top1k"
MAX_WORKERS = 10

def get_top_packages(limit=1000):
    """
    Fetches top packages using `npm search` which is more reliable than the public API endpoint 
    from a script, and falls back to a hardcoded high-value list.
    """
    print(f"[*] Fetching list of top packages...")
    packages = set()

    # 1. Hardcoded "Gold Standard" list (Top ~50 most depended on) to guarantee core libs
    # These are universally accepted as benign in research papers.
    core_packages = [
        "lodash", "react", "chalk", "request", "commander", "react-dom", "express", "debug", 
        "prop-types", "fs-extra", "async", "bluebird", "uuid", "moment", "axios", "tslib", 
        "glob", "underscore", "classnames", "body-parser", "yargs", "mkdirp", "webpack", 
        "babel-core", "inquirer", "minimist", "colors", "rxjs", "zone.js", "core-js", 
        "semver", "aws-sdk", "through2", "cheerio", "fs", "net", "http", "object-assign", 
        "promise", "q", "qs", "vue", "jquery", "bootstrap", "typescript", "eslint", 
        "jest", "mocha", "redux", "socket.io", "superagent", "morgan", "cors", "validator",
        "winston", "dotenv", "multer", "mongoose", "sequelize", "redis", "mysql", "pg",
        "passport", "jsonwebtoken", "bcrypt", "nodemailer", "pm2", "nodemon", "forever",
        "grunt", "gulp", "bower", "browserify", "yeoman-generator", "karma", "coffee-script",
        "shelljs", "nan", "fsevents", "node-gyp", "node-pre-gyp", "tar", "fstream",
        "rimraf", "abbrev", "accepts", "acorn", "adm-zip", "after", "agentkeepalive"
    ]
    packages.update(core_packages)

    # 2. Try to get more via npm search if we need them
    if len(packages) < limit:
        try:
             # Search for popular keywords to fill the list
            keywords = ["react", "webpack", "babel", "plugin", "ui", "server", "data", "util"]
            for kw in keywords:
                if len(packages) >= limit: break
                
                cmd = ["npm", "search", kw, "--json", "--searchlimit", "100"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    try:
                        data = json.loads(result.stdout)
                        for item in data:
                            packages.add(item['name'])
                    except:
                        pass
        except Exception as e:
            print(f"Warning: npm search failed: {e}")
            
    return list(packages)[:limit]

def download_package(package_name):
    """
    Downloads the latest version of a package using `npm pack`.
    """
    try:
        # Check if already exists (approximate check)
        if any(f.startswith(package_name.replace("/", "-")) for f in os.listdir(OUTPUT_DIR)):
            return "EXISTS"

        cmd = ["npm", "pack", package_name, "--pack-destination", OUTPUT_DIR]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            return "OK"
        else:
            return f"FAIL: {result.stderr.strip()}"
    except Exception as e:
        return f"ERROR: {e}"

def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        
    print(f"[*] Output directory: {OUTPUT_DIR}")
    
    # Get the list
    packages = get_top_packages(TOP_N)
    print(f"[*] Discovered {len(packages)} packages. Starting download...")
    
    # Download in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(download_package, packages))
        
    # Stats
    successful = results.count("OK") + results.count("EXISTS")
    print(f"[*] Download complete. Successfully have {successful}/{len(packages)} packages.")

if __name__ == "__main__":
    main()

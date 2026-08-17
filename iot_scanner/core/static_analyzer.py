import os
import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# List of sensitive files to check for
SENSITIVE_FILES = [
    "/etc/shadow", "/etc/passwd", "/etc/ssh/ssh_host_key", 
    "/etc/ssh/ssh_host_rsa_key", "/root/.ssh/id_rsa", 
    "/root/.bash_history", "/etc/config/network", "/etc/shadow.bak"
]

# Smarter Suspicious Patterns
SUSPICIOUS_PATTERNS = [
    (r"backdoor", "Potential backdoor mention"),
    (r"nc\s+-e\s+/\w+", "Reverse shell attempt (nc -e)"),
    (r"eval\(\s*base64_decode", "PHP base64 execution"),
    (r"admin:admin|root:root|user:user", "Hardcoded default credentials"),
    (r"chmod\s+777", "Insecure file permissions"),
    (r"telnetd.*-p", "Custom telnet server port"),
    (r"wget\s+http://[0-9.]+/.*\|.*sh", "Suspicious remote script execution"),
]

# Dangerous C functions (potential for buffer overflows / injection)
DANGEROUS_FUNCTIONS = [
    "strcpy", "strcat", "gets", "sprintf", "vsprintf", "system", "popen", "execl", "execve"
]

class StaticAnalyzer:
    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        self.findings = []

    def check_sensitive_files(self):
        logger.info("Checking for sensitive files...")
        for rel_path in SENSITIVE_FILES:
            target_path = os.path.join(self.target_dir, rel_path.lstrip("/"))
            if os.path.exists(target_path):
                self.findings.append({
                    "type": "Sensitive File",
                    "file": rel_path,
                    "description": f"Found sensitive file: {rel_path}"
                })
                
                if rel_path.endswith("shadow") or rel_path.endswith("shadow.bak"):
                    self._parse_shadow(target_path, rel_path)

    def _parse_shadow(self, file_path, rel_path):
        """Extracts accounts and detects weak/empty passwords."""
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        user = parts[0]
                        pwd_hash = parts[1]
                        if pwd_hash in ["", "*", "!", "!!"]:
                            continue 
                        
                        self.findings.append({
                            "type": "Credential Audit",
                            "file": rel_path,
                            "description": f"Found password hash for user: {user}. Check for weak passwords."
                        })
        except Exception as e:
            logger.error(f"Error parsing {rel_path}: {e}")

    def check_suspicious_patterns(self):
        logger.info("Scanning for suspicious patterns and dangerous functions...")
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.target_dir)
                
                # 1. Text-based patterns
                if file.endswith(('.sh', '.php', '.py', '.txt', '.js', '.conf', '.json', '.html')):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for pattern, label in SUSPICIOUS_PATTERNS:
                                if re.search(pattern, content, re.IGNORECASE):
                                    self.findings.append({
                                        "type": "Suspicious Pattern",
                                        "file": rel_path,
                                        "description": f"{label} found: '{pattern}'"
                                    })
                    except Exception: pass

                # 2. Binary-based dangerous functions 
                is_binary = any(rel_path.startswith(d) for d in ['bin', 'sbin', 'usr/bin', 'usr/sbin', 'lib'])
                if is_binary or file.endswith(('.so', '.bin', '.exe')):
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read(512 * 1024) # Read first 512KB
                            strings = re.findall(b"[A-Za-z0-9_]{4,}", content)
                            found_funcs = []
                            for s in strings:
                                func_name = s.decode('ascii', errors='ignore')
                                if func_name in DANGEROUS_FUNCTIONS:
                                    found_funcs.append(func_name)
                            
                            if found_funcs:
                                unique_funcs = list(set(found_funcs))
                                self.findings.append({
                                    "type": "Dangerous Function",
                                    "file": rel_path,
                                    "description": f"Found risky C functions in binary: {', '.join(unique_funcs)}"
                                })
                    except Exception: pass

    def run_analysis(self):
        
        self.check_sensitive_files()
        self.check_suspicious_patterns()
        logger.info(f"Static analysis completed. Found {len(self.findings)} issues.")
        return self.findings


if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        analyzer = StaticAnalyzer(sys.argv[1])
        results = analyzer.run_analysis()
        print(json.dumps(results, indent=2))

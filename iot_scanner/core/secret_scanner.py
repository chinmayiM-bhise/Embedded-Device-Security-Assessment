import re
import os
import math
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Basic patterns
PATTERNS = {
    "SSH Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "API Key": r"(api_key|apikey|secret_key|api_secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]",
    "Generic Password/Token": r"(password|passwd|pwd|pass|token|auth)\s*[:=]\s*['\"]([a-zA-Z0-9_\-!@#$%^&*()]{6,64})['\"]",
}

def calculate_entropy(data):
    """Calculates the Shannon Entropy of a string."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

# Common alphabets to ignore in entropy analysis
COMMON_ALPHABETS = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789abcdef",
    "0123456789ABCDEF"
]

def is_common_alphabet(word):
    
    for alphabet in COMMON_ALPHABETS:
        if alphabet in word or word in alphabet:
            return True
    if len(word) > 10:
        if all(ord(word[i+1]) == ord(word[i]) + 1 for i in range(len(word)-1)):
            return True
    return False

class SecretScanner:
    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        self.findings = []

    def scan_file(self, file_path: str):
        """Scans for secrets using Regex and Entropy heuristics."""
        
        filename = os.path.basename(file_path).lower()
        rel_path = os.path.relpath(file_path, self.target_dir)
        
        if filename.endswith(('.crt', '.pem', '.pub', '.key.pub')) or "ca-certificates" in filename:
            return

        
        if filename.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz')):
            return

        try:
            
            with open(file_path, 'rb') as f:
                raw_content = f.read(1024 * 1024) 
                content = raw_content.decode('utf-8', errors='ignore')
                matched_ranges = []

                # 1. Pattern Matching (Regex) 
                for label, pattern in PATTERNS.items():
                    flags = re.IGNORECASE if label in ["API Key", "Generic Password/Token"] else 0
                    for match in re.finditer(pattern, content, flags=flags):
                        start, end = match.span()
                        if not any(max(start, m_s) < min(end, m_e) for m_s, m_e in matched_ranges):
                            self.findings.append({
                                "type": label,
                                "file": rel_path,
                                "match": match.group(0),
                                "line": content.count('\n', 0, start) + 1,
                                "method": "Regex"
                            })
                            matched_ranges.append((start, end))

                # 2. Entropy Analysis
                entropy_extensions = ('.conf', '.config', '.cfg', '.ini', '.sh', '.py', '.php', '.js', '.html', '.xml', '.yaml', '.yml', '.json', '.txt', '.txt')
                is_binary_dir = any(x in rel_path.split(os.sep) for x in ['bin', 'sbin', 'lib', 'usr', 'etc/ssl'])
                is_so_file = filename.endswith(('.so', '.bin', '.exe', '.elf'))

                if not is_so_file and (filename.endswith(entropy_extensions) or not is_binary_dir):
                    words = re.findall(r'[a-zA-Z0-9/\+=]{24,}', content) 
                    for word in words:
                        if is_common_alphabet(word):
                            continue
                            
                        entropy = calculate_entropy(word)
                        #  (keys usually > 4.7)
                        if entropy > 4.8:
                            if word not in [f["match"] for f in self.findings]:
                                self.findings.append({
                                    "type": "High Entropy String (Potential Key)",
                                    "file": rel_path,
                                    "match": word[:60] + "...",
                                    "line": "N/A",
                                    "method": f"Entropy ({entropy:.2f})"
                                })

        except Exception as e:
            logger.debug(f"Could not read {file_path}: {e}")

    def scan_directory(self):
        logger.info(f"Scanning for secrets in {self.target_dir}...")
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                self.scan_file(os.path.join(root, file))
        return self.findings

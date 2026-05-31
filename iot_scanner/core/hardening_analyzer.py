import os
import logging
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HardeningAnalyzer:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.findings = []

    def is_elf(self, file_path):
        """Check if a file is an ELF binary."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                return header == b'\x7fELF'
        except Exception:
            return False

    def check_hardening(self, file_path):
        """Analyze an ELF binary for security hardening features."""
        results = {
            "file": os.path.relpath(file_path, self.target_dir),
            "nx": False,
            "pie": False,
            "canary": False,
            "relro": "None"
        }
        
        try:
            with open(file_path, 'rb') as f:
                elffile = ELFFile(f)
                
                # 1. Check for NX (No-Execute) - Look for GNU_STACK segment with no 'X'
                for segment in elffile.iter_segments():
                    if segment.header.p_type == 'PT_GNU_STACK':
                        if not (segment.header.p_flags & 0x1): # 0x1 is PF_X
                            results["nx"] = True
                
                # 2. Check for PIE (Position Independent Executable)
                if elffile.header.e_type == 'ET_DYN':
                    results["pie"] = True

                # 3. Check for Stack Canaries - Look for __stack_chk_fail symbol
                for section in elffile.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            if '__stack_chk_fail' in symbol.name:
                                results["canary"] = True
                                break
                
                # 4. Check for RELRO (Relocation Read-Only)
                has_relro_segment = False
                for segment in elffile.iter_segments():
                    if segment.header.p_type == 'PT_GNU_RELRO':
                        has_relro_segment = True
                        break
                
                if has_relro_segment:
                   
                    results["relro"] = "Partial"
                    dynamic = elffile.get_section_by_name('.dynamic')
                    if dynamic:
                        for tag in dynamic.iter_tags():
                            if tag.entry.d_tag == 'DT_BIND_NOW' or (tag.entry.d_tag == 'DT_FLAGS' and tag.entry.d_val & 0x8):
                                results["relro"] = "Full"
                                break

        except Exception as e:
            logger.debug(f"Error analyzing {file_path}: {e}")
            return None
            
        return results

    def run_analysis(self, max_binaries=20):
        """Scan binaries and return hardening report."""
        logger.info(f"Analyzing binary hardening in {self.target_dir}...")
        count = 0
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if self.is_elf(file_path):
                    hardening = self.check_hardening(file_path)
                    if hardening:
                        self.findings.append(hardening)
                        count += 1
                if count >= max_binaries:
                    break
            if count >= max_binaries:
                break
        
        return self.findings

if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        analyzer = HardeningAnalyzer(sys.argv[1])
        print(json.dumps(analyzer.run_analysis(), indent=2))

import os
import logging
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Dangerous libc C functions categorized by risk
DANGEROUS_LIBC_FUNCTIONS = {
    # Command Injection / Shell Execution (Critical)
    "system": {"category": "Command Injection", "severity": "Critical", "description": "Spawns shell execution with user parameters."},
    "popen": {"category": "Command Injection", "severity": "Critical", "description": "Opens bidirectional pipe to process shell."},
    "execl": {"category": "Process Execution", "severity": "High", "description": "Direct binary execution call."},
    "execve": {"category": "Process Execution", "severity": "High", "description": "Direct binary execution call with environment."},
    "execvp": {"category": "Process Execution", "severity": "High", "description": "Direct binary execution call with PATH resolution."},

    # Buffer Overflow & Memory Corruption (High)
    "strcpy": {"category": "Buffer Overflow", "severity": "High", "description": "Unbounded string copy prone to stack/heap overflow."},
    "strcat": {"category": "Buffer Overflow", "severity": "High", "description": "Unbounded string concatenation."},
    "gets": {"category": "Buffer Overflow", "severity": "Critical", "description": "Deprecated unsafe input function with no bounds check."},
    "sprintf": {"category": "Format String / Overflow", "severity": "High", "description": "Unbounded formatted string printing."},
    "vsprintf": {"category": "Format String / Overflow", "severity": "High", "description": "Unbounded variable argument formatted printing."},
    "scanf": {"category": "Format String / Overflow", "severity": "Medium", "description": "Unsafe formatted scan if %s length is omitted."},
}

ARCH_MAP = {
    'EM_MIPS': 'MIPS',
    'EM_MIPS_RS3_LE': 'MIPS (RS3000 LE)',
    'EM_ARM': 'ARM (32-bit)',
    'EM_AARCH64': 'ARM (64-bit / AArch64)',
    'EM_386': 'x86 (32-bit)',
    'EM_X86_64': 'x86_64 (64-bit)',
    'EM_PPC': 'PowerPC (32-bit)',
    'EM_PPC64': 'PowerPC (64-bit)',
    'EM_RISCV': 'RISC-V',
    'EM_SH': 'SuperH (SH4)',
    'EM_SPARC': 'SPARC',
    'EM_ARC': 'Synopsys ARC',
    'EM_XTENSA': 'Tensilica Xtensa (ESP32/IoT)'
}

class HardeningAnalyzer:
    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        self.findings = []
        self.detected_architectures = set()

    def is_elf(self, file_path: str) -> bool:
        """Check if a file begins with standard ELF magic bytes."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                return header == b'\x7fELF'
        except Exception:
            return False

    def _extract_dangerous_symbols(self, elffile: ELFFile) -> list:
        """Inspects ELF Symbol and Relocation Tables for dangerous libc imports."""
        dangerous_found = []
        found_names = set()

        # 1. Inspect Symbol Tables (.dynsym and .symtab)
        for section in elffile.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    s_name = symbol.name
                    if s_name in DANGEROUS_LIBC_FUNCTIONS and s_name not in found_names:
                        found_names.add(s_name)
                        meta = DANGEROUS_LIBC_FUNCTIONS[s_name]
                        dangerous_found.append({
                            "function": s_name,
                            "category": meta["category"],
                            "severity": meta["severity"],
                            "description": meta["description"],
                            "source": section.name
                        })

        # 2. Inspect Relocation Sections (.rel.plt / .rela.plt)
        for section in elffile.iter_sections():
            if isinstance(section, RelocationSection):
                symtab = elffile.get_section(section.header.sh_link)
                if symtab:
                    for rel in section.iter_relocations():
                        if rel.entry.r_info_sym < symtab.num_symbols():
                            symbol = symtab.get_symbol(rel.entry.r_info_sym)
                            s_name = symbol.name
                            if s_name in DANGEROUS_LIBC_FUNCTIONS and s_name not in found_names:
                                found_names.add(s_name)
                                meta = DANGEROUS_LIBC_FUNCTIONS[s_name]
                                dangerous_found.append({
                                    "function": s_name,
                                    "category": meta["category"],
                                    "severity": meta["severity"],
                                    "description": meta["description"],
                                    "source": section.name
                                })

        return dangerous_found

    def check_hardening(self, file_path: str) -> dict:
        """Analyze an ELF binary for architecture, compiler mitigations, and dangerous symbols."""
        results = {
            "file": os.path.relpath(file_path, self.target_dir).replace('\\', '/'),
            "arch": "Unknown",
            "bits": 32,
            "endian": "Little-Endian",
            "nx": False,
            "pie": False,
            "canary": False,
            "relro": "None",
            "dangerous_functions": []
        }

        try:
            with open(file_path, 'rb') as f:
                elffile = ELFFile(f)

                # 1. Architecture & Endianness
                e_machine = elffile.header.get('e_machine', 'Unknown')
                arch_name = ARCH_MAP.get(e_machine, str(e_machine))
                endian_name = "Little-Endian" if elffile.little_endian else "Big-Endian"
                results["arch"] = f"{arch_name} ({endian_name})"
                results["bits"] = elffile.elfclass
                results["endian"] = endian_name
                self.detected_architectures.add(results["arch"])

                # 2. Check for NX (No-Execute stack)
                for segment in elffile.iter_segments():
                    if segment.header.p_type == 'PT_GNU_STACK':
                        if not (segment.header.p_flags & 0x1): # 0x1 is PF_X
                            results["nx"] = True

                # 3. Check for PIE (Position Independent Executable)
                if elffile.header.e_type == 'ET_DYN':
                    results["pie"] = True

                # 4. Check for Stack Canaries (__stack_chk_fail or __stack_chk_guard)
                for section in elffile.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            if '__stack_chk_fail' in symbol.name or '__stack_chk_guard' in symbol.name:
                                results["canary"] = True
                                break

                # 5. Check for RELRO (Relocation Read-Only)
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

                # 6. Extract Dangerous Imported Symbols via PLT/DynSym
                results["dangerous_functions"] = self._extract_dangerous_symbols(elffile)

        except Exception as e:
            logger.debug(f"Error analyzing ELF {file_path}: {e}")
            return None

        return results

    def run_analysis(self, max_binaries: int = 30) -> list:
        """Scan binaries in target directory and return hardening and symbol analysis."""
        logger.info(f"Analyzing binary hardening and dynamic symbols in {self.target_dir}...")
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

        logger.info(f"Binary analysis completed: {len(self.findings)} ELF binaries audited. Architectures: {list(self.detected_architectures)}")
        return self.findings

if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        analyzer = HardeningAnalyzer(sys.argv[1])
        print(json.dumps(analyzer.run_analysis(), indent=2))
    else:
        print("Usage: python hardening_analyzer.py <directory_to_scan>")

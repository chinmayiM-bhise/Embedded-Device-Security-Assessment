from fpdf import FPDF
import os
from datetime import datetime

class SecurityReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, 'CONFIDENTIAL - IOT FIRMWARE SECURITY AUDIT REPORT', 0, 0, 'L')
        self.cell(0, 10, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', 0, 1, 'R')
        self.set_draw_color(59, 130, 246) 
        self.line(10, 18, 200, 18)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

    def section_title(self, title, color=(59, 130, 246)):
        self.ln(5)
        self.set_font('Arial', 'B', 14)
        self.set_text_color(*color)
        self.cell(0, 10, title.upper(), 0, 1, 'L')
        self.set_draw_color(*color)
        self.line(self.get_x(), self.get_y(), self.get_x() + 190, self.get_y())
        self.ln(5)

    def draw_severity_badge(self, severity):
        colors = {
            'Critical': (239, 68, 68),
            'CISA KEV': (220, 38, 38),
            'High': (245, 158, 11),
            'Medium': (59, 130, 246),
            'Low': (16, 185, 129),
            'PASS': (16, 185, 129),
            'FAIL': (239, 68, 68)
        }
        color = colors.get(severity, (150, 150, 150))
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font('Arial', 'B', 8)
        self.cell(22, 5, severity.upper(), 0, 0, 'C', 1)
        self.set_text_color(0, 0, 0) 

def calculate_security_score(data):
    """Calculates a security score from 0 to 100 with fail-safe extraction guards."""
    extraction_status = data.get('extraction_status', 'SUCCESS')
    has_rootfs = data.get('has_rootfs', True)

    # Fail-safe guard: If extraction failed or yielded no root filesystem, score is N/A
    if extraction_status == "FAILED" or not has_rootfs:
        return "N/A"

    score = 100

    # 1. CVE Deductions
    cve_deduction = 0
    for vuln in data.get('vulnerability_scan', {}).get('vulnerabilities', []):
        if vuln.get('is_cisa_kev'): cve_deduction += 35
        elif vuln.get('severity') == 'Critical': cve_deduction += 25
        elif vuln.get('severity') == 'High': cve_deduction += 15
        elif vuln.get('severity') == 'Medium': cve_deduction += 8
        else: cve_deduction += 4

    score -= min(70, cve_deduction)

    # 2. Malware Deductions
    malware_count = len(data.get('malware_analysis', []))
    score -= min(80, malware_count * 40)

    # 3. Secrets Deductions
    secret_count = len(data.get('secrets', []))
    if secret_count > 0:
        secret_deduction = 5 + (secret_count * 2)
        score -= min(30, secret_deduction)

    # 4. Hardening Deductions
    hardening = data.get('hardening_analysis', [])
    if hardening:
        total_binaries = len(hardening)
        missing_nx = sum(1 for h in hardening if not h.get('nx'))
        missing_pie = sum(1 for h in hardening if not h.get('pie'))
        hardening_deduction = ((missing_nx + missing_pie) / (2 * total_binaries)) * 15
        score -= hardening_deduction

    return max(0, min(100, int(score)))

def generate_pdf_report(data, output_path):
    score = calculate_security_score(data)
    extraction_failed = (score == "N/A")

    if extraction_failed:
        grade = "N/A"
        grade_color = (245, 158, 11)
        rating_text = "Overall Security Rating: N/A (Extraction Incomplete)"
    else:
        grade = "A" if score >= 90 else ("B" if score >= 80 else ("C" if score >= 70 else ("D" if score >= 60 else "F")))
        grade_color = (16, 185, 129) if score >= 80 else ((245, 158, 11) if score >= 60 else (239, 68, 68))
        rating_text = f"Overall Security Rating: {score}/100"

    pdf = SecurityReport()
    pdf.alias_nb_pages()
    pdf.add_page()

    # --- COVER PAGE ---
    pdf.ln(40)
    pdf.set_font('Arial', 'B', 28)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 20, 'IoT Firmware Audit', 0, 1, 'C')
    pdf.set_font('Arial', '', 18)
    pdf.cell(0, 10, 'Automated Security Assessment', 0, 1, 'C')

    pdf.ln(20)
    pdf.set_draw_color(200, 200, 200)
    pdf.line(50, pdf.get_y(), 160, pdf.get_y())
    pdf.ln(20)

    # Big Grade Circle
    pdf.set_font('Arial', 'B', 60)
    pdf.set_text_color(*grade_color)
    pdf.cell(0, 40, str(grade), 0, 1, 'C')
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, rating_text, 0, 1, 'C')

    pdf.ln(30)
    pdf.set_text_color(100, 100, 100)
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 5, f'Target: {data.get("firmware", "Unknown")}', 0, 1, 'C')
    pdf.cell(0, 5, f'Audit ID: {os.path.basename(os.path.dirname(output_path))}', 0, 1, 'C')

    pdf.add_page()

    # --- EXECUTIVE SUMMARY ---
    pdf.section_title('Executive Summary')
    pdf.set_font('Arial', '', 11)
    pdf.set_text_color(0, 0, 0)
    
    if extraction_failed:
        pdf.set_fill_color(254, 242, 242)
        pdf.set_text_color(185, 28, 28)
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 8, ' [!] EXTRACTION NOTICE: FIRMWARE FILESYSTEM UNPARSEABLE', 1, 1, 'L', 1)
        pdf.set_font('Arial', '', 9)
        pdf.multi_cell(0, 5, 
            "The internal root filesystem could not be decompressed. The target file may be encrypted, "
            "digitally signed, use proprietary vendor headers, or non-standard compression. "
            "Deep analysis of components, CVEs, secrets, and binary hardening could not be performed.", 1, 'L', 1)
        pdf.ln(5)
        pdf.set_text_color(0, 0, 0)

    summary_text = f"This report provides a security analysis of the firmware binary '{data.get('firmware', 'Unknown')}'. " \
                   f"The assessment covered binary forensics, vulnerability scanning, malware detection, secret discovery, hardening analysis, and OWASP compliance."
    pdf.multi_cell(0, 6, summary_text)

    pdf.ln(5)
    # Quick Stats Table
    pdf.set_fill_color(248, 250, 252)
    pdf.set_font('Arial', 'B', 10)
    pdf.cell(95, 10, 'Metric', 1, 0, 'L', 1)
    pdf.cell(95, 10, 'Result', 1, 1, 'L', 1)
    pdf.set_font('Arial', '', 10)

    comp_info = data.get("compliance", {})
    comp_score_str = comp_info.get("compliance_score", "N/A")

    metrics = [
        ('Extraction Status', 'Success (RootFS Parsed)' if not extraction_failed else 'Incomplete / Encrypted'),
        ('OWASP IoT (2024) Compliance', comp_score_str),
        ('Total Vulnerabilities (CVEs)', len(data.get('vulnerability_scan', {}).get('vulnerabilities', []))),
        ('Malware / Botnet Indicators', len(data.get('malware_analysis', []))),
        ('Discovered Secrets & Keys', len(data.get('secrets', []))),
        ('Static Analysis Findings', len(data.get('static_analysis', []))),
        ('Binaries Analyzed', len(data.get('hardening_analysis', [])))
    ]
    for label, val in metrics:
        pdf.cell(95, 8, label, 1)
        pdf.cell(95, 8, str(val), 1, 1)

    # --- OWASP COMPLIANCE AUDIT ---
    if comp_info and comp_info.get("categories"):
        pdf.ln(5)
        pdf.section_title('OWASP IoT Top 10 (2024) Compliance Audit', color=(14, 116, 144))
        pdf.set_font('Arial', 'B', 9)
        pdf.set_fill_color(241, 245, 249)
        pdf.cell(20, 8, 'ID', 1, 0, 'C', 1)
        pdf.cell(100, 8, 'Category & Description', 1, 0, 'L', 1)
        pdf.cell(30, 8, 'Status', 1, 0, 'C', 1)
        pdf.cell(40, 8, 'Findings', 1, 1, 'C', 1)

        pdf.set_font('Arial', '', 8)
        for cat in comp_info["categories"]:
            pdf.cell(20, 7, cat["id"], 1, 0, 'C')
            pdf.cell(100, 7, f" {cat['title'][:45]}", 1, 0, 'L')
            if cat["status"] == "PASS":
                pdf.set_text_color(16, 185, 129)
                pdf.cell(30, 7, 'COMPLIANT', 1, 0, 'C')
            elif cat["status"] == "FAIL":
                pdf.set_text_color(239, 68, 68)
                pdf.cell(30, 7, 'VIOLATION', 1, 0, 'C')
            else:
                pdf.set_text_color(150, 150, 150)
                pdf.cell(30, 7, 'N/A', 1, 0, 'C')
            pdf.set_text_color(0, 0, 0)
            pdf.cell(40, 7, str(cat["findings_count"]), 1, 1, 'C')

    # --- MALWARE ANALYSIS ---
    pdf.add_page()
    pdf.section_title('Malware & Botnet Analysis', color=(239, 68, 68))
    if not data.get('malware_analysis'):
        pdf.set_text_color(16, 185, 129)
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 10, 'CLEAN: No known malware or botnet indicators detected.', 0, 1)
    else:
        for m in data['malware_analysis']:
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(0, 8, f'TARGET: {os.path.basename(m.get("file", "unknown"))}', 0, 1)
            pdf.set_font('Arial', 'I', 9)
            pdf.cell(0, 5, f'Path: {m.get("file", "N/A")}', 0, 1)

            pdf.set_font('Arial', '', 10)
            if 'detections' in m:
                for d in m['detections']:
                    pdf.ln(1)
                    pdf.set_text_color(239, 68, 68)
                    pdf.cell(10, 5, '>> ', 0, 0)
                    pdf.set_text_color(0, 0, 0)
                    pdf.multi_cell(0, 5, f"[{d.get('method', 'Detection')}] {d.get('family', 'Malware')}: {d.get('description', '')}")
            else:
                pdf.multi_cell(0, 5, m.get('description', 'Detected via pattern matching'))
            pdf.ln(4)

    # --- VULNERABILITIES ---
    pdf.add_page()
    pdf.section_title('Vulnerability Assessment (CVEs & CISA KEV)')
    vulnerabilities = data.get('vulnerability_scan', {}).get('vulnerabilities', [])
    if not vulnerabilities:
        pdf.cell(0, 10, 'No known vulnerabilities identified for detected components.', 0, 1)
    else:
        for v in vulnerabilities:
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(45, 8, v.get('cve_id', 'CVE-Unknown'), 0, 0)
            
            if v.get('is_cisa_kev'):
                pdf.draw_severity_badge('CISA KEV')
            else:
                pdf.draw_severity_badge(v.get('severity', 'Medium'))

            pdf.set_font('Arial', 'B', 11)
            pdf.cell(0, 8, f'  {v.get("component", "Unknown")} (v{v.get("version", "N/A")})', 0, 1)

            if v.get('is_cisa_kev'):
                pdf.set_fill_color(254, 242, 242)
                pdf.set_text_color(185, 28, 28)
                pdf.set_font('Arial', 'B', 8)
                pdf.cell(0, 5, ' [!] CISA KEV: Actively weaponized and exploited in the wild!', 1, 1, 'L', 1)
                pdf.set_text_color(0, 0, 0)

            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(0, 5, f"Description: {v.get('description', 'No description available.')}")

            pdf.set_fill_color(240, 247, 255)
            pdf.set_font('Arial', 'B', 9)
            pdf.cell(0, 6, ' RECOMMENDED REMEDIATION:', 0, 1, 'L', 1)
            pdf.set_font('Arial', '', 9)
            pdf.multi_cell(0, 5, v.get('remediation', 'Update to latest version.'), 0, 'L', 1)
            pdf.ln(5)

    # --- STATIC ANALYSIS ---
    pdf.add_page()
    pdf.section_title('Static Analysis Findings', color=(168, 85, 247))

    if not data.get('static_analysis'):
        pdf.cell(0, 10, 'No significant static analysis issues detected.', 0, 1)
    else:
        for s in data['static_analysis']:
            pdf.set_font('Arial', 'B', 10)
            pdf.set_text_color(0, 0, 0)
            file_name = os.path.basename(s.get('file', 'unknown'))
            pdf.cell(0, 6, f"{s.get('type', 'Issue')} in {file_name}", 0, 1)
            pdf.set_font('Arial', '', 8)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 4, f"Path: {s.get('file', 'N/A')}", 0, 1)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(0, 5, f"Description: {s.get('description', 'Suspicious behavior detected')}")
            pdf.ln(3)        

    # --- SECRETS ---
    pdf.section_title('Credential & Key Discovery')
    if not data.get('secrets'):
        pdf.cell(0, 10, 'No hardcoded secrets or private keys identified.', 0, 1)
    else:
        for s in data['secrets']:
            pdf.set_font('Arial', 'B', 10)
            pdf.cell(0, 6, f"{s.get('type', 'Secret')} in {os.path.basename(s.get('file', 'unknown'))}", 0, 1)
            pdf.set_font('Arial', '', 8)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 4, f"Path: {s.get('file', 'N/A')} | Method: {s.get('method', 'N/A')}", 0, 1)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)
            pdf.set_font('Courier', '', 8)
            pdf.set_fill_color(245, 245, 245)
            pdf.multi_cell(0, 4, s.get('match', '').strip()[:200], 1, 'L', 1)
            pdf.ln(3)

    # --- HARDENING ---
    pdf.add_page()
    pdf.section_title('Binary Hardening Analysis')
    if not data.get('hardening_analysis'):
        pdf.cell(0, 10, 'No ELF binaries were identified for hardening analysis.', 0, 1)
    else:
        pdf.set_fill_color(59, 130, 246)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Arial', 'B', 9)
        pdf.cell(70, 8, ' Binary File (Arch)', 1, 0, 'L', 1)
        pdf.cell(30, 8, ' NX', 1, 0, 'C', 1)
        pdf.cell(30, 8, ' PIE', 1, 0, 'C', 1)
        pdf.cell(30, 8, ' Canary', 1, 0, 'C', 1)
        pdf.cell(30, 8, ' RELRO', 1, 1, 'C', 1)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font('Arial', '', 8)
        for h in data['hardening_analysis'][:25]:
            fname = os.path.basename(h.get('file', 'unknown'))
            arch_badge = h.get('arch', 'ELF')
            pdf.cell(70, 7, f" {fname[:18]} ({arch_badge[:12]})", 1)
            pdf.set_text_color(16, 185, 129) if h.get('nx') else pdf.set_text_color(239, 68, 68)
            pdf.cell(30, 7, 'ENABLED' if h.get('nx') else 'DISABLED', 1, 0, 'C')
            pdf.set_text_color(16, 185, 129) if h.get('pie') else pdf.set_text_color(239, 68, 68)
            pdf.cell(30, 7, 'ENABLED' if h.get('pie') else 'DISABLED', 1, 0, 'C')
            pdf.set_text_color(16, 185, 129) if h.get('canary') else pdf.set_text_color(239, 68, 68)
            pdf.cell(30, 7, 'PROTECTED' if h.get('canary') else 'VULNERABLE', 1, 0, 'C')
            pdf.set_text_color(16, 185, 129) if h.get('relro') == 'Full' else (pdf.set_text_color(245, 158, 11) if h.get('relro') == 'Partial' else pdf.set_text_color(239, 68, 68))
            pdf.cell(30, 7, h.get('relro', 'None').upper(), 1, 1, 'C')
            pdf.set_text_color(0, 0, 0)

            dangerous = h.get('dangerous_functions', [])
            if dangerous:
                pdf.set_font('Arial', 'I', 7)
                pdf.set_text_color(185, 28, 28)
                func_names = [f"{d['function']} ({d['category']})" for d in dangerous]
                pdf.cell(0, 4, f"   >> Unsafe Libc Calls: {', '.join(func_names)}", 0, 1)
                pdf.set_font('Arial', '', 8)
                pdf.set_text_color(0, 0, 0)

    pdf.output(output_path)
    return output_path

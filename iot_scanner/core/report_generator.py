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
            'High': (245, 158, 11),
            'Medium': (59, 130, 246),
            'Low': (16, 185, 129)
        }
        color = colors.get(severity, (150, 150, 150))
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font('Arial', 'B', 8)
        self.cell(20, 5, severity.upper(), 0, 0, 'C', 1)
        self.set_text_color(0, 0, 0) 

def calculate_security_score(data):
    """Calculates a security score from 0 to 100 with improved balancing."""
    if not data.get('vulnerability_scan', {}).get('components') and \
       not data.get('secrets') and \
       not data.get('malware_analysis') and \
       not data.get('binary_analysis', {}).get('types'):
        return 50

    score = 100

    # 2. CVE Deductions
    cve_deduction = 0
    for vuln in data.get('vulnerability_scan', {}).get('vulnerabilities', []):
        if vuln['severity'] == 'Critical': cve_deduction += 25
        elif vuln['severity'] == 'High': cve_deduction += 15
        elif vuln['severity'] == 'Medium': cve_deduction += 8
        else: cve_deduction += 4

    score -= min(70, cve_deduction)

    # 3. Malware Deductions
    malware_count = len(data.get('malware_analysis', []))
    score -= min(80, malware_count * 40)

    # 4. Secrets Deductions
    secret_count = len(data.get('secrets', []))
    if secret_count > 0:
        secret_deduction = 5 + (secret_count * 2)
        score -= min(30, secret_deduction)

    # 5. Hardening Deductions
    hardening = data.get('hardening_analysis', [])
    if hardening:
        total_binaries = len(hardening)
        missing_nx = sum(1 for h in hardening if not h['nx'])
        missing_pie = sum(1 for h in hardening if not h['pie'])
        hardening_deduction = ((missing_nx + missing_pie) / (2 * total_binaries)) * 15
        score -= hardening_deduction

    return max(0, min(100, int(score)))

def generate_pdf_report(data, output_path):
    score = calculate_security_score(data)
    grade = "A" if score >= 90 else ("B" if score >= 80 else ("C" if score >= 70 else ("D" if score >= 60 else "F")))
    grade_color = (16, 185, 129) if score >= 80 else ((245, 158, 11) if score >= 60 else (239, 68, 68))

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
    pdf.cell(0, 40, grade, 0, 1, 'C')
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, f'Overall Security Rating: {score}/100', 0, 1, 'C')

    pdf.ln(30)
    pdf.set_text_color(100, 100, 100)
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 5, f'Target: {data["firmware"]}', 0, 1, 'C')
    pdf.cell(0, 5, f'Audit ID: {os.path.basename(os.path.dirname(output_path))}', 0, 1, 'C')

    pdf.add_page()

    # --- EXECUTIVE SUMMARY ---
    pdf.section_title('Executive Summary')
    pdf.set_font('Arial', '', 11)
    pdf.set_text_color(0, 0, 0)
    summary_text = f"This report provides a comprehensive security analysis of the firmware binary '{data['firmware']}'. " \
                   f"The assessment covered vulnerability scanning, malware detection, secret discovery, and binary hardening analysis."
    pdf.multi_cell(0, 6, summary_text)

    pdf.ln(5)
    # Quick Stats Table
    pdf.set_fill_color(248, 250, 252)
    pdf.set_font('Arial', 'B', 10)
    pdf.cell(95, 10, 'Metric', 1, 0, 'L', 1)
    pdf.cell(95, 10, 'Result', 1, 1, 'L', 1)
    pdf.set_font('Arial', '', 10)

    metrics = [
        ('Total Vulnerabilities (CVEs)', len(data['vulnerability_scan']['vulnerabilities'])),
        ('Malware / Botnet Indicators', len(data['malware_analysis'])),
        ('Discovered Secrets & Keys', len(data['secrets'])),
        ('Static Analysis Findings', len(data['static_analysis'])),
        ('Binaries Analyzed', len(data['hardening_analysis']))
    ]
    for label, val in metrics:
        pdf.cell(95, 8, label, 1)
        pdf.cell(95, 8, str(val), 1, 1)

    # --- MALWARE ANALYSIS ---
    pdf.section_title('Malware & Botnet Analysis', color=(239, 68, 68))
    if not data['malware_analysis']:
        pdf.set_text_color(16, 185, 129)
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 10, 'CLEAN: No known malware or botnet indicators detected.', 0, 1)
    else:
        for m in data['malware_analysis']:
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Arial', 'B', 11)
            family = m.get('malware_family', m.get('summary', 'Suspicious Object'))
            pdf.cell(0, 8, f'TARGET: {os.path.basename(m["file"])}', 0, 1)
            pdf.set_font('Arial', 'I', 9)
            pdf.cell(0, 5, f'Path: {m["file"]}', 0, 1)

            pdf.set_font('Arial', '', 10)
            if 'detections' in m:
                for d in m['detections']:
                    pdf.ln(1)
                    pdf.set_text_color(239, 68, 68)
                    pdf.cell(10, 5, '>> ', 0, 0)
                    pdf.set_text_color(0, 0, 0)
                    pdf.multi_cell(0, 5, f"[{d['method']}] {d['family']}: {d['description']}")
            else:
                pdf.multi_cell(0, 5, m.get('description', 'Detected via pattern matching'))
            pdf.ln(4)

    # --- VULNERABILITIES ---
    pdf.add_page()
    pdf.section_title('Vulnerability Assessment (CVEs)')
    if not data['vulnerability_scan']['vulnerabilities']:
        pdf.cell(0, 10, 'No known vulnerabilities identified for detected components.', 0, 1)
    else:
        for v in data['vulnerability_scan']['vulnerabilities']:
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(40, 8, v['cve_id'], 0, 0)
            pdf.draw_severity_badge(v['severity'])
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(0, 8, f'  {v["component"]} (v{v["version"]})', 0, 1)

            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(0, 5, f"Description: {v['description']}")

            pdf.set_fill_color(240, 247, 255)
            pdf.set_font('Arial', 'B', 9)
            pdf.cell(0, 6, ' RECOMMENDED REMEDIATION:', 0, 1, 'L', 1)
            pdf.set_font('Arial', '', 9)
            pdf.multi_cell(0, 5, v['remediation'], 0, 'L', 1)
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

            # File name
            file_name = os.path.basename(s.get('file', 'unknown'))
            pdf.cell(0, 6, f"{s.get('type', 'Issue')} in {file_name}", 0, 1)

            # Path
            pdf.set_font('Arial', '', 8)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 4, f"Path: {s.get('file', 'N/A')}", 0, 1)

            # Description
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(0, 5, f"Description: {s.get('description', 'Suspicious behavior detected')}")

            # Optional severity (if exists)
            if 'severity' in s:
                pdf.ln(1)
                pdf.draw_severity_badge(s['severity'])

            pdf.ln(5)        

    # --- SECRETS ---
    pdf.section_title('Credential & Key Discovery')
    if not data['secrets']:
        pdf.cell(0, 10, 'No hardcoded secrets or private keys identified.', 0, 1)
    else:
        for s in data['secrets']:
            pdf.set_font('Arial', 'B', 10)
            pdf.cell(0, 6, f"{s['type']} in {os.path.basename(s['file'])}", 0, 1)
            pdf.set_font('Arial', '', 8)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 4, f"Path: {s['file']} | Method: {s['method']}", 0, 1)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)
            pdf.set_font('Courier', '', 8)
            pdf.set_fill_color(245, 245, 245)
            pdf.multi_cell(0, 4, s['match'].strip()[:200], 1, 'L', 1)
            pdf.ln(3)

    # --- HARDENING ---
    pdf.add_page()
    pdf.section_title('Binary Hardening Analysis')
    if not data['hardening_analysis']:
        pdf.cell(0, 10, 'No ELF binaries were identified for hardening analysis.', 0, 1)
    else:
        # Table Header
        pdf.set_fill_color(59, 130, 246)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Arial', 'B', 9)
        pdf.cell(80, 8, ' Binary File', 1, 0, 'L', 1)
        pdf.cell(35, 8, ' NX', 1, 0, 'C', 1)
        pdf.cell(35, 8, ' PIE', 1, 0, 'C', 1)
        pdf.cell(40, 8, ' Stack Canary', 1, 1, 'C', 1)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font('Arial', '', 8)
        for h in data['hardening_analysis'][:30]: 
            pdf.cell(80, 7, f" {os.path.basename(h['file'])}", 1)
            pdf.set_text_color(16, 185, 129) if h['nx'] else pdf.set_text_color(239, 68, 68)
            pdf.cell(35, 7, 'ENABLED' if h['nx'] else 'DISABLED', 1, 0, 'C')
            pdf.set_text_color(16, 185, 129) if h['pie'] else pdf.set_text_color(239, 68, 68)
            pdf.cell(35, 7, 'ENABLED' if h['pie'] else 'DISABLED', 1, 0, 'C')
            pdf.set_text_color(16, 185, 129) if h['canary'] else pdf.set_text_color(239, 68, 68)
            pdf.cell(40, 7, 'PROTECTED' if h['canary'] else 'VULNERABLE', 1, 1, 'C')
            pdf.set_text_color(0, 0, 0)

    pdf.output(output_path)
    return output_path


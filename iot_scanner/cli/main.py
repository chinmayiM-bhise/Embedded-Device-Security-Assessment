import click
import os
import json
import uuid
import logging
from iot_scanner.core.extractor import extract_firmware
from iot_scanner.core.secret_scanner import SecretScanner
from iot_scanner.core.static_analyzer import StaticAnalyzer
from iot_scanner.core.vulnerability_scanner import VulnerabilityScanner
from iot_scanner.core.hardening_analyzer import HardeningAnalyzer
from iot_scanner.core.malware_scanner import MalwareScanner
from iot_scanner.core.binary_scanner import BinaryScanner
from iot_scanner.core.report_generator import generate_pdf_report, calculate_security_score
from iot_scanner.core.sbom_generator import generate_cyclonedx_sbom, save_sbom_json
from iot_scanner.core.database import save_scan

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

@click.group()
def cli():
    """IoT Firmware Security Scanner - Enterprise CLI"""
    pass

@cli.command()
@click.argument('firmware_path', type=click.Path(exists=True))
@click.option('--output', '-o', default='cli_results', help='Output directory.')
def scan(firmware_path, output):
    """Run a full enterprise security audit on a firmware file."""
    scan_id = str(uuid.uuid4())
    filename = os.path.basename(firmware_path)
    
    if not os.path.exists(output):
        os.makedirs(output, exist_ok=True)
    extracted_dir = os.path.join(output, "extracted")
    
    try:
        click.echo(f"[*] Starting Audit: {filename} (ID: {scan_id})")
        
        # 0. Forensics
        bin_results = BinaryScanner(firmware_path).run_scan()
        
        # 1. Extraction
        extraction_meta = extract_firmware(firmware_path, extracted_dir)
        target_scan_dir = extraction_meta.get("rootfs_dir", extracted_dir)
        has_rootfs = extraction_meta.get("has_rootfs", False)
        
        if not has_rootfs:
            click.secho(
                "[!] WARNING: Firmware extraction did not yield a standard Linux root filesystem.\n"
                "    The image may be encrypted, use proprietary headers, or unsupported compression.",
                fg="yellow"
            )
        
        # 2-6. Deep Scanning
        secrets = SecretScanner(target_scan_dir).scan_directory() if extraction_meta["total_files"] > 0 else []
        statics = StaticAnalyzer(target_scan_dir).run_analysis() if has_rootfs else []
        vulns = VulnerabilityScanner(target_scan_dir).run_scan() if extraction_meta["total_files"] > 0 else {"components": [], "vulnerabilities": []}
        harden = HardeningAnalyzer(target_scan_dir).run_analysis() if extraction_meta["total_files"] > 0 else []
        malware = MalwareScanner(target_scan_dir).run_scan() if extraction_meta["total_files"] > 0 else []
        
        final_results = {
            "firmware": filename,
            "extraction_status": extraction_meta.get("status", "SUCCESS"),
            "has_rootfs": has_rootfs,
            "total_files_extracted": extraction_meta.get("total_files", 0),
            "binary_analysis": bin_results,
            "secrets": secrets,
            "static_analysis": statics,
            "vulnerability_scan": vulns,
            "hardening_analysis": harden,
            "malware_analysis": malware
        }
        
        final_results["security_score"] = calculate_security_score(final_results)
        
        # Save Results JSON
        with open(os.path.join(output, "results.json"), 'w') as f:
            json.dump(final_results, f, indent=4)
            
        # Generate PDF Report
        pdf_path = os.path.join(output, "audit_report.pdf")
        generate_pdf_report(final_results, pdf_path)

        # Generate CycloneDX SBOM
        sbom_data = generate_cyclonedx_sbom(
            components=vulns.get("components", []),
            vulnerabilities=vulns.get("vulnerabilities", []),
            firmware_name=filename
        )
        sbom_path = os.path.join(output, "sbom_cyclonedx.json")
        save_sbom_json(sbom_data, sbom_path)
        
        # Save to DB
        save_scan(scan_id, filename, final_results)
        
        score_display = f"{final_results['security_score']}/100" if final_results['security_score'] != "N/A" else "N/A (Extraction Incomplete)"
        click.echo(f"[*] Audit Complete! Security Score: {score_display}")
        click.echo(f"[*] PDF Report: {pdf_path}")
        click.echo(f"[*] CycloneDX SBOM: {sbom_path}")
        click.echo(f"[*] Results JSON: {os.path.join(output, 'results.json')}")
        click.echo(f"[*] Scan ID saved to database: {scan_id}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)

if __name__ == '__main__':
    cli()

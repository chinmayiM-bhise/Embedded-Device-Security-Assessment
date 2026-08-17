from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import os
import shutil
import uuid
import json
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
from iot_scanner.core.compliance import evaluate_owasp_compliance
from iot_scanner.core.database import save_scan, get_all_scans

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="IoT Firmware Security Scanner", version="1.2.0")
app.mount("/static", StaticFiles(directory="iot_scanner/web/static"), name="static")

UPLOAD_DIR = "uploads"
RESULTS_DIR = "results"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

scans = {}

def run_scan_task(scan_id: str, firmware_path: str, filename: str):
    try:
        output_dir = os.path.join(RESULTS_DIR, scan_id)
        extracted_dir = os.path.join(output_dir, "extracted")
        os.makedirs(extracted_dir, exist_ok=True)

        scans[scan_id]["status"] = "Forensics"
        bin_results = BinaryScanner(firmware_path).run_scan()

        scans[scan_id]["status"] = "Extracting"
        extraction_meta = extract_firmware(firmware_path, extracted_dir)
        target_scan_dir = extraction_meta.get("rootfs_dir", extracted_dir)
        has_rootfs = extraction_meta.get("has_rootfs", False)

        scans[scan_id]["status"] = "Scanning"
        
        # Deep inspection of extracted rootfs
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
        final_results["compliance"] = evaluate_owasp_compliance(final_results)

        # Generate Enterprise PDF Report
        pdf_path = os.path.join(output_dir, "report.pdf")
        generate_pdf_report(final_results, pdf_path)

        # Generate CycloneDX 1.5 JSON SBOM
        sbom_data = generate_cyclonedx_sbom(
            components=vulns.get("components", []),
            vulnerabilities=vulns.get("vulnerabilities", []),
            firmware_name=filename
        )
        sbom_path = os.path.join(output_dir, "sbom_cyclonedx.json")
        save_sbom_json(sbom_data, sbom_path)

        # Save to database
        save_scan(scan_id, filename, final_results)
        
        scans[scan_id].update({
            "status": "Completed",
            "results": final_results,
            "pdf_url": f"/download/{scan_id}",
            "sbom_url": f"/sbom/{scan_id}",
            "extraction_status": extraction_meta.get("status", "SUCCESS"),
            "has_rootfs": has_rootfs
        })

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        scans[scan_id]["status"] = "Failed"
        scans[scan_id]["error"] = str(e)

@app.post("/upload")
async def upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    scan_id = str(uuid.uuid4())
    path = os.path.join(UPLOAD_DIR, f"{scan_id}_{file.filename}")
    with open(path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    scans[scan_id] = {"status": "Started", "filename": file.filename}
    background_tasks.add_task(run_scan_task, scan_id, path, file.filename)
    return {"scan_id": scan_id}

@app.get("/status/{scan_id}")
async def status(scan_id: str):
    res = scans.get(scan_id, {"status": "Not Found"})
    if scan_id in scans:
        res["extraction_empty"] = not scans[scan_id].get("has_rootfs", True)
        res["extraction_status"] = scans[scan_id].get("extraction_status", "UNKNOWN")
    return res

@app.get("/results/{scan_id}")
async def results(scan_id: str):
    if scan_id in scans and scans[scan_id]["status"] == "Completed":
        return scans[scan_id]["results"]
    raise HTTPException(status_code=404)

@app.get("/download/{scan_id}")
async def download(scan_id: str):
    path = os.path.join(RESULTS_DIR, scan_id, "report.pdf")
    if os.path.exists(path):
        return FileResponse(path, filename="Security_Audit_Report.pdf")
    raise HTTPException(status_code=404)

@app.get("/sbom/{scan_id}")
async def download_sbom(scan_id: str):
    path = os.path.join(RESULTS_DIR, scan_id, "sbom_cyclonedx.json")
    if os.path.exists(path):
        return FileResponse(path, filename="CycloneDX_SBOM.json", media_type="application/json")
    raise HTTPException(status_code=404, detail="SBOM not generated for this scan.")

@app.get("/history")
async def history():
    return [{"id": s.id, "file": s.filename, "date": s.timestamp.isoformat()} for s in get_all_scans()]

@app.get("/")
async def root():
    return FileResponse("iot_scanner/web/static/index.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)

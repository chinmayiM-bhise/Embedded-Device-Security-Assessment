import os
import shutil
import logging
import tarfile
import zipfile
import gzip
import subprocess
import lzma

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ExtractionError(Exception):
    pass

FIRMWARE_EXTENSIONS = ('.bin', '.img', '.chk', '.trx', '.squashfs', '.rom', '.fw', '.iso', '.qcow2')
ARCHIVE_EXTENSIONS = ('.zip', '.tar', '.gz', '.tgz', '.tar.gz', '.tar.bz2', '.bz2', '.xz', '.tar.xz')
ROOTFS_INDICATORS = ('etc', 'bin', 'sbin', 'usr', 'var', 'www', 'lib', 'root')

def custom_python_extractor(file_path: str, output_dir: str) -> bool:
    """Extracts standard archive formats using Python built-in modules."""
    extracted = False
    try:
        # Check if it's a zip file
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)
            extracted = True
        # Check if it's a tar file
        elif tarfile.is_tarfile(file_path):
            with tarfile.open(file_path, 'r:*') as tar_ref:
                tar_ref.extractall(output_dir)
            extracted = True
        # Check for GZIP
        elif file_path.endswith(('.gz', '.tgz')) and not file_path.endswith('.tar.gz'):
            with gzip.open(file_path, 'rb') as f_in:
                out_name = os.path.basename(file_path).replace('.tgz', '.tar').replace('.gz', '') or "extracted_data"
                with open(os.path.join(output_dir, out_name), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            extracted = True
        # Check for XZ/LZMA
        elif file_path.endswith(('.xz', '.txz')) and not file_path.endswith('.tar.xz'):
            with lzma.open(file_path, 'rb') as f_in:
                out_name = os.path.basename(file_path).replace('.txz', '.tar').replace('.xz', '') or "extracted_data"
                with open(os.path.join(output_dir, out_name), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            extracted = True
    except Exception as e:
        logger.error(f"Custom extraction failed for {file_path}: {e}")
    return extracted

def try_binwalk_extract(file_path: str, output_dir: str) -> bool:
    """Attempts extraction using binwalk if installed on the host."""
    try:
        result = subprocess.run(
            ["binwalk", "-e", "-M", "--directory", output_dir, file_path],
            capture_output=True,
            text=True,
            timeout=120
        )
        extracted_dirs = [d for d in os.listdir(output_dir) if d.endswith('.extracted')]
        if extracted_dirs:
            logger.info(f"Binwalk extracted directories: {extracted_dirs}")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
        logger.debug(f"Binwalk extraction not available or timed out: {e}")
    except Exception as e:
        logger.debug(f"Binwalk execution error: {e}")
    return False

def validate_rootfs(directory: str):
    """
    Analyzes an extracted directory to verify if a valid POSIX/Linux rootfs was extracted.
    Returns:
        tuple: (has_rootfs: bool, total_files: int, best_root_path: str)
    """
    total_files = 0
    best_root_path = directory
    max_indicators = 0

    if not os.path.exists(directory):
        return False, 0, directory

    for root, dirs, files in os.walk(directory):
        total_files += len(files)
        # Check how many standard rootfs folders exist at this directory level
        matched_indicators = sum(1 for indicator in ROOTFS_INDICATORS if indicator in dirs)
        if matched_indicators > max_indicators:
            max_indicators = matched_indicators
            best_root_path = root

    has_rootfs = max_indicators >= 2 or (total_files > 5 and max_indicators >= 1)
    return has_rootfs, total_files, best_root_path

def unpack_nested_firmware(target_dir: str, depth: int = 1, max_depth: int = 3):
    """
    Recursively scans extracted contents for inner firmware images or archives 
    and unpacks them into place.
    """
    if depth > max_depth or not os.path.exists(target_dir):
        return

    candidates = []
    for root, _, files in os.walk(target_dir):
        # Prevent re-scanning deeply nested .extracted folders infinitely
        if root.count('.extracted') > max_depth:
            continue
        for file in files:
            file_lower = file.lower()
            file_path = os.path.join(root, file)
            # Skip empty files
            if os.path.getsize(file_path) == 0:
                continue

            if file_lower.endswith(FIRMWARE_EXTENSIONS) or file_lower.endswith(ARCHIVE_EXTENSIONS):
                candidates.append(file_path)

    for candidate in candidates:
        nested_out = candidate + ".extracted"
        if not os.path.exists(nested_out):
            os.makedirs(nested_out, exist_ok=True)
            logger.info(f"[Depth {depth}] Unpacking nested firmware container: {os.path.basename(candidate)}")
            
            extracted = try_binwalk_extract(candidate, nested_out)
            if not extracted:
                extracted = custom_python_extractor(candidate, nested_out)

            if extracted:
                unpack_nested_firmware(nested_out, depth=depth + 1, max_depth=max_depth)

def extract_firmware(file_path: str, output_dir: str) -> dict:
    """
    Robust multi-tier firmware extractor with recursive inner image unpacking
    and root filesystem verification.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    logger.info(f"Starting extraction for {file_path} into {output_dir}")

    # Step 1: Initial extraction
    initial_extracted = False
    
    # Try custom python archive extractor first for speed on zip/tar
    if custom_python_extractor(file_path, output_dir):
        initial_extracted = True
        logger.info("Archive extracted via custom Python extractor.")
    else:
        # Fall back to binwalk
        initial_extracted = try_binwalk_extract(file_path, output_dir)

    # Step 2: Unpack any nested firmware binaries (e.g., .zip containing .bin)
    unpack_nested_firmware(output_dir, depth=1, max_depth=3)

    # Step 3: Validate rootfs
    has_rootfs, total_files, best_root = validate_rootfs(output_dir)

    # Step 4: If completely empty, copy the raw file for binary-only fallback
    if total_files == 0:
        logger.warning(f"Extraction yielded 0 files for {file_path}. Keeping raw binary copy.")
        shutil.copy(file_path, os.path.join(output_dir, os.path.basename(file_path)))
        total_files = 1

    extraction_meta = {
        "output_dir": output_dir,
        "rootfs_dir": best_root if has_rootfs else output_dir,
        "has_rootfs": has_rootfs,
        "total_files": total_files,
        "status": "SUCCESS" if has_rootfs else ("PARTIAL" if total_files > 1 else "FAILED")
    }

    logger.info(f"Extraction Summary -> Status: {extraction_meta['status']}, Files: {total_files}, RootFS Detected: {has_rootfs}")
    return extraction_meta

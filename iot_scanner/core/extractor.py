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

def custom_python_extractor(file_path, output_dir):
    
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
        elif file_path.endswith('.gz'):
            with gzip.open(file_path, 'rb') as f_in:
                
                out_name = os.path.basename(file_path)[:-3] or "extracted_data"
                with open(os.path.join(output_dir, out_name), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            extracted = True
        # Check for XZ/LZMA
        elif file_path.endswith('.xz'):
            with lzma.open(file_path, 'rb') as f_in:
                out_name = os.path.basename(file_path)[:-3] or "extracted_data"
                with open(os.path.join(output_dir, out_name), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            extracted = True
    except Exception as e:
        logger.error(f"Custom extraction failed for {file_path}: {e}")
    return extracted

def extract_firmware(file_path: str, output_dir: str):
    """Tries multiple extraction methods to unpack firmware."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    logger.info(f"Starting extraction for {file_path} into {output_dir}")

    # 1. Try Binwalk (the gold standard for firmware)
    try:
        # -e: extract
        # -M: Matryoshka (recursive)
        
        result = subprocess.run(
            ["binwalk", "-e", "-M", "--directory", output_dir, file_path], 
            capture_output=True, 
            text=True, 
            timeout=120
        )
        
        
        extracted_dirs = [d for d in os.listdir(output_dir) if d.endswith('.extracted')]
        if extracted_dirs:
            logger.info(f"Binwalk successfully extracted data to {extracted_dirs}")
            
            return output_dir
            
    except subprocess.TimeoutExpired:
        logger.error(f"Binwalk timed out extracting {file_path}")
    except Exception as e:
        logger.debug(f"Binwalk execution error: {e}")

    # 2. Fallback to Custom Python Extractor
    if custom_python_extractor(file_path, output_dir):
        logger.info("Custom Python extractor succeeded.")
        return output_dir

    # 3. Final attempt:analyze as-is
    if not os.listdir(output_dir):
        logger.warning(f"Could not extract {file_path}. Copying as a single file for analysis.")
        shutil.copy(file_path, os.path.join(output_dir, os.path.basename(file_path)))
        
    return output_dir


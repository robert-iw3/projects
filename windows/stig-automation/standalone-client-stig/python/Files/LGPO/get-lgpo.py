# Python script to automatically download and extract LGPO.exe
# from the official Microsoft direct link (stable for years, still valid Nov 2025)
# Places LGPO.exe directly in the folder where you run the script

import os
import requests
from pathlib import Path
from zipfile import ZipFile

# Configuration
LGPO_URL = "https://download.microsoft.com/download/8/5/E/85E2F2B7-6B58-4B4F-9A4F-5D86B00F7D3E/LGPO.zip"
CURRENT_DIR = Path.cwd()
EXE_PATH = CURRENT_DIR / "LGPO.exe"
ZIP_PATH = CURRENT_DIR / "LGPO.zip"

# If LGPO.exe already exists, do nothing
if EXE_PATH.exists():
    print("LGPO.exe is already present in the current directory.")
    exit()

print("Downloading LGPO.zip from Microsoft...", flush=True)

try:
    response = requests.get(LGPO_URL, stream=True)
    response.raise_for_status()

    # Write with progress feedback (optional but nice)
    total_size = int(response.headers.get('content-length', 0))
    downloaded = 0
    with open(ZIP_PATH, "wb") as f:
        for chunk in response.iter_content(chunk_size=1024*1024):  # 1MB chunks
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    print(f"\rProgress: {percent:.1f}%", end="", flush=True)
    print("\nDownload complete.")
except Exception as e:
    print(f"Download failed: {e}")
    exit(1)

print("Extracting LGPO.exe to current directory...", flush=True)
try:
    with ZipFile(ZIP_PATH, 'r') as zip_ref:
        zip_ref.extractall(CURRENT_DIR)  # LGPO.exe is in root of zip
except Exception as e:
    print(f"Extraction failed: {e}")
    exit(1)

# Clean up the zip file
ZIP_PATH.unlink()
print("Cleanup complete.")

print("\nLGPO.exe is now ready in:")
print(CURRENT_DIR)
import os
import json
import subprocess
from multiprocessing import Pool
from pathlib import Path

SCANCODE_DIR = "./scancode-toolkit/scancode-toolkit-32.2.0"
COMPONENTS_FILE = "components.json"  # Save components data from initial step here
OUTPUT_NOTICE = "NOTICE-with-scancode.md"

def run_scancode_for_url(args):
    url, index = args
    # Prepare workspace per component
    work_dir = Path(f"./scancode_runs/run_{index}")
    work_dir.mkdir(parents=True, exist_ok=True)

    # Download the source code archive or clone repo to work_dir here
    # Example: Use `git clone` if url is a git repo (simplified, more robust is recommended)
    if url.endswith(".git"):
        subprocess.run(["git", "clone", url, str(work_dir)], check=True)
    else:
        # For other URLs, download source archive and extract (dummy example)
        archive_path = work_dir / "source.zip"
        subprocess.run(["wget", "-q", "-O", str(archive_path), url], check=True)
        subprocess.run(["unzip", "-qq", str(archive_path), "-d", str(work_dir)], check=True)

    # Run ScanCode on the extracted/cloned source
    output_json = work_dir / "scancode_result.json"
    scan_cmd = [
        os.path.join(SCANCODE_DIR, "scancode"),
        "--copyright",
        "--license",
        "--json-pp",
        str(output_json),
        str(work_dir),
    ]
    subprocess.run(scan_cmd, check=True)
    
    # Parse ScanCode output to extract copyrights (simplified)
    with open(output_json) as f:
        data = json.load(f)
    copyrights = []
    for file_data in data.get("files", []):
        for cr in file_data.get("copyrights", []):
            copyrights.append(cr.get("value"))
    # Consolidate unique copyrights
    unique_cr = "\n".join(sorted(set(c for c in copyrights if c)))
    return index, unique_cr

def main():
    # Load initial components list saved during first step (you must save this from generate_notice.py)
    with open(COMPONENTS_FILE) as f:
        components = json.load(f)

    # Run parallel ScanCode scans on component URLs
    urls = [(c["url"], idx) for idx, c in enumerate(components) if c["url"]]

    with Pool(min(len(urls), 6)) as pool:  # limit concurrency concurrency
        results = pool.map(run_scancode_for_url, urls)

    # Map index to copyright info
    idx_copyright = {idx: cr for idx, cr in results}

    # Generate updated NOTICE with ScanCode copyrights
    with open(OUTPUT_NOTICE, "w") as f:
        f.write("# NOTICE with ScanCode Copyrights\n\n")
        f.write("| Component | Version | URL | Copyright (ScanCode) | License |\n")
        f.write("|-----------|---------|-----|---------------------|---------|\n")
        for idx, c in enumerate(components):
            scancode_cr = idx_copyright.get(idx, c.get("copyright", ""))
            f.write(f"| {c['component']} | {c['version']} | {c['url']} | {scancode_cr} | {c['license']} |\n")

    print(f"Updated NOTICE file generated with ScanCode copyrights: {OUTPUT_NOTICE}")

if __name__ == "__main__":
    main()

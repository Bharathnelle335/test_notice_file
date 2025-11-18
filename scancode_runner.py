import os
import json
import subprocess
from multiprocessing import Pool
from pathlib import Path

SCANCODE_DIR = "./scancode-toolkit/scancode-toolkit-32.2.0"
COMPONENTS_FILE = "components.json"
OUTPUT_NOTICE = "NOTICE-with-scancode.md"

def scan_component(args):
    url, idx = args
    work_dir = Path(f"./scancode_runs/run_{idx}")
    work_dir.mkdir(parents=True, exist_ok=True)

    # Dummy implementation: Assume git clone for .git URLs else skip real download
    try:
        if url.endswith(".git"):
            subprocess.run(["git", "clone", url, str(work_dir)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # Skipping actual download for non-git URL for now — extend as needed
            pass
    
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
        
        with open(output_json) as f:
            data = json.load(f)
        
        copyrights = []
        for file_data in data.get("files", []):
            for cr in file_data.get("copyrights", []):
                v = cr.get("value")
                if v:
                    copyrights.append(v)
        unique_cr = "\n".join(sorted(set(c for c in copyrights if c)))
        return idx, unique_cr
    except Exception as e:
        print(f"ScanCode failed for URL {url} : {e}")
        return idx, ""

def main():
    with open(COMPONENTS_FILE) as f:
        components = json.load(f)

    urls = [(c["url"], idx) for idx, c in enumerate(components) if c["url"]]

    with Pool(min(6, len(urls))) as pool:
        results = pool.map(scan_component, urls)

    idx_to_cr = {idx: cr for idx, cr in results}

    with open(OUTPUT_NOTICE, "w") as f:
        f.write("# NOTICE with ScanCode Copyrights\n\n")
        f.write("| Component | Version | URL | Copyright (ScanCode) | License |\n")
        f.write("|-----------|---------|-----|---------------------|---------|\n")
        for idx, comp in enumerate(components):
            cr = idx_to_cr.get(idx, comp.get("copyright", ""))
            f.write(f"| {comp['component']} | {comp['version']} | {comp['url']} | {cr} | {comp['license']} |\n")

    print(f"Generated {OUTPUT_NOTICE}")

if __name__ == "__main__":
    main()

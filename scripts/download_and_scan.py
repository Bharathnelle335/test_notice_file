import os
import sys
import argparse
import subprocess
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--component", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--purl", required=False, default="")
    parser.add_argument("--url", required=False, default="")
    args = parser.parse_args()

    component = args.component
    version = args.version
    purl = args.purl
    url = args.url

    workdir = Path(f"scan-results/{component}")
    workdir.mkdir(parents=True, exist_ok=True)

    # TODO: Implement source downloading/cloning logic here if needed.
    # For MVP, assume source is available locally or skip download.

    # Run ScanCode
    output_file = workdir / f"{component}.json"
    scan_cmd = [
        "scancode",
        "-cl",
        "--license-text",
        "--json-pp",
        str(output_file),
        "."  # Scan current directory
    ]
    try:
        subprocess.run(scan_cmd, check=True)
    except Exception as e:
        print(f"ScanCode failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

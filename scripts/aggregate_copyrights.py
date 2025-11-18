import json
from pathlib import Path

def extract_copyrights(scan_json):
    copyrights = []
    for f in scan_json.get("files", []):
        for cr in f.get("copyrights", []):
            v = cr.get("value")
            if v:
                copyrights.append(v.strip())
    return list(set(copyrights))

def main():
    scan_results_path = Path("scan-results")
    output_path = Path("copyrights.txt")
    lines = []
    for scan_dir in scan_results_path.iterdir():
        if scan_dir.is_dir():
            component_name = scan_dir.name
            # Find the JSON file for the component
            json_files = list(scan_dir.glob("*.json"))
            if not json_files:
                continue
            scan_file = json_files[0]  # Assuming one JSON per component
            data = json.loads(scan_file.read_text(encoding="utf-8"))
            cr_list = extract_copyrights(data)
            lines.append(f"Component: {component_name}\n")
            if cr_list:
                lines.extend([f"  {cr}" for cr in cr_list])
            else:
                lines.append("  No copyright info found.")
            lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")

if __name__ == "__main__":
    main()

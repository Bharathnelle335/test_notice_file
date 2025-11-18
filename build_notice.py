import json
import os
from pathlib import Path

scans_dir = Path("scans")
rows = []
license_texts = {}

for art_dir in scans_dir.iterdir():
    if not art_dir.is_dir():
        continue
    scan_path = art_dir / "scan.json"
    meta_path = art_dir / "meta.json"
    if not scan_path.exists():
        continue
    scan_data = json.loads(scan_path.read_text(encoding="utf-8"))
    meta = {}
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    name = meta.get("name") or art_dir.name
    version = meta.get("version") or ""
    url = meta.get("url") or ""
    lic = meta.get("license") or ""

    copyrights = []
    ltexts = {}

    for f in scan_data.get("files", []):
        for cpr in f.get("copyrights", []):
            v = cpr.get("value")
            if v:
                copyrights.append(v.strip())
        for det in f.get("license_detections", []):
            key = det.get("license_expression_spdx") or det.get("license_expression") or det.get("license_key")
            for m in det.get("matches", []) or []:
                t = (m.get("matched_text") or "").strip()
                if t and key and key not in ltexts:
                    ltexts[key] = t

    seen = set()
    unique_copyrights = []
    for c in copyrights:
        if c not in seen:
            seen.add(c)
            unique_copyrights.append(c)

    rows.append({
        "name": name,
        "version": version,
        "url": url,
        "license": lic,
        "copyright": "\n".join(unique_copyrights[:25])
    })

    for k, v in ltexts.items():
        license_texts.setdefault(k, v)

out = []
out.append(f"# {os.environ.get('TITLE', 'Open Source Notices')}\n")

for r in rows:
    out.append(f"### {r['name']} {r['version']}")
    if r.get("url"):
        out.append(f"- **URL:** {r['url']}")
    if r.get("license"):
        out.append(f"- **License:** {r['license']}")
    if r.get("copyright"):
        out.append(f"- **Copyright:** {r['copyright']}")
    out.append("")

if license_texts:
    out.append("\n## License Texts\n")
    for lid, text in sorted(license_texts.items()):
        out.append(f"### {lid}\n``````\n")

Path("NOTICE.md").write_text(("\n".join(out)).rstrip() + "\n", encoding="utf-8")

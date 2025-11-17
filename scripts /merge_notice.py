import json, os
from pathlib import Path

title = os.getenv("TITLE", "Open Source Notices")
scans_dir = Path("scans")
rows = []
license_texts = {}

# Each unpacked directory contains scan.json + meta.json
for p in scans_dir.glob("*/*/scan.json"):
    meta = p.parent / "meta.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    meta_d = {}
    if meta.exists():
        meta_d = json.loads(meta.read_text(encoding="utf-8"))

    name = meta_d.get("name") or p.parent.name
    version = meta_d.get("version") or ""
    url = meta_d.get("url") or ""
    lic = meta_d.get("license") or ""

    cps = []
    ltexts = {}

    # Collect copyrights from ScanCode
    for f in data.get("files", []):
        for cpr in f.get("copyrights", []):
            v = cpr.get("value")
            if v:
                cps.append(v.strip())

        # Collect license texts
        for det in f.get("license_detections", []):
            key = det.get("license_expression_spdx") or det.get("license_expression") or det.get("license_key")
            for m in det.get("matches", []) or []:
                t = (m.get("matched_text") or "").strip()
                if t and key and key not in ltexts:
                    ltexts[key] = t

    # Deduplicate copyrights
    seen = set()
    cps_u = []
    for ln in cps:
        if ln not in seen:
            seen.add(ln)
            cps_u.append(ln)

    rows.append({
        "name": name,
        "version": version,
        "url": url,
        "license": lic,
        "copyright": "\n".join(cps_u)  # <-- All copyrights included
    })

    for k, v in ltexts.items():
        license_texts.setdefault(k, v)

# Build NOTICE.md
out = []
out.append(f"# {title}\n")
for r in rows:
    out.append(f"### {r['name']}" + (f" {r['version']}" if r.get('version') else ""))
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
        out.append(f"### {lid}\n```text\n{text.strip()}\n```\n")

Path("NOTICE.md").write_text(("\n".join(out)).rstrip() + "\n", encoding="utf-8")

with open(os.environ.get("GITHUB_OUTPUT", "github_output.txt"), "a") as gh:
    gh.write(f"count={len(rows)}\n")

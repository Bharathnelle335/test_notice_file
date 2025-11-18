
import json, os
from pathlib import Path

title = os.getenv("TITLE", "Open Source Notices")
scans_dir = Path("scans")
rows = []
license_texts = {}

# Each unpacked directory contains scan.json + meta.json
for p in scans_dir.glob("**/scan.json"):
    meta = p.parent / "meta.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    meta_d = {}
    if meta.exists():
        meta_d = json.loads(meta.read_text(encoding="utf-8"))

    # Extract component name and simplify to last part after '/'
    raw_name = meta_d.get("name") or p.parent.name
    # Normalize repo tail as component name
last = raw_name.split('/')[-1] if raw_name else ''
name = last.split('@')[0] if last else ''

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
        "copyright": "
".join(cps_u)  # Include all copyrights
    })

    for k, v in ltexts.items():
        license_texts.setdefault(k, v)

# Build NOTICE.md
out = []
out.append(f"# {title}
")
for r in rows:
    line = f"{r['name']}"
    if r.get('version'):
        line += f" {r['version']}"
    out.append(line)
    if r.get("url"):
        out.append(f"URL: {r['url']}")
    if r.get("license"):
        out.append(f"License: {r['license']}")
    if r.get("copyright"):
        out.append(f"Copyright:
{r['copyright']}")
    out.append("")

if license_texts:
    out.append("
## License Texts
")
    for lid, text in sorted(license_texts.items()):
        out.append(f"### {lid}
```text
{text.strip()}
```
")

Path("NOTICE.md").write_text(("
".join(out)).rstrip() + "
", encoding="utf-8")

with open(os.environ.get("GITHUB_OUTPUT", "github_output.txt"), "a") as gh:
    gh.write(f"count={len(rows)}
")

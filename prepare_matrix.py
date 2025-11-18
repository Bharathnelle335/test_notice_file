import json, os, re

NOASSERT = {"NOASSERT", "NONE", "", None}

def norm(s):
    if s is None:
        return None
    s = str(s).strip()
    return None if (not s or s.upper() in NOASSERT) else " ".join(s.split())

def detect(doc):
    if isinstance(doc, dict):
        if doc.get("bomFormat") == "CycloneDX" or "components" in doc:
            return "cdx"
        if doc.get("spdxVersion") or doc.get("SPDXID") or "packages" in doc or "files" in doc:
            return "spdx"
    return "unknown"

def parse_spdx(doc):
    res = []
    for p in doc.get("packages") or []:
        name = norm(p.get("name"))
        if not name:
            continue
        version = norm(p.get("versionInfo"))
        lic = norm(p.get("licenseConcluded")) or norm(p.get("licenseDeclared"))
        if not lic:
            infos = p.get("licenseInfoFromFiles") or []
            toks = sorted(set([norm(x) for x in infos if norm(x)]))
            lic = " AND ".join(toks) if toks else None
        homepage = norm(p.get("homepage"))
        dl = norm(p.get("downloadLocation"))
        url = dl or homepage
        purl = None
        for ref in p.get("externalRefs") or []:
            rtype = (ref.get("referenceType") or "").lower()
            loc = norm(ref.get("referenceLocator"))
            if "purl" in rtype and loc:
                purl = loc
                break
        res.append({"name": name, "version": version, "license": lic, "url": url, "purl": purl})
    return res

def parse_cdx(doc):
    res = []
    for c in doc.get("components") or []:
        name = norm(c.get("name"))
        if not name:
            continue
        version = norm(c.get("version"))
        purl = norm(c.get("purl"))
        lic = None
        if c.get("licenses"):
            exprs = [norm(x.get("expression")) for x in c["licenses"] if isinstance(x, dict) and x.get("expression")]
            if exprs and exprs[0]:
                lic = exprs[0]
            else:
                ids = []
                for entry in c["licenses"]:
                    licd = entry.get("license") if isinstance(entry, dict) else None
                    if isinstance(licd, dict):
                        lid = norm(licd.get("id"))
                        lname = norm(licd.get("name"))
                        if lid:
                            ids.append(lid)
                        elif lname:
                            ids.append(lname)
                ids = sorted(set(ids))
                lic = " AND ".join(ids) if ids else None
        url = None
        for ref in c.get("externalReferences") or []:
            rtype = (ref.get("type") or "").lower()
            u = norm(ref.get("url"))
            if rtype in {"website", "vcs", "distribution", "documentation", "release-notes"} and u:
                url = u
                break
        res.append({"name": name, "version": version, "license": lic, "url": url, "purl": purl})
    return res

def slug(s: str, maxlen: int = 120) -> str:
    if not s:
        return "component"
    s = re.sub(r'["<>|*?:\\/\r\n]', '-', s)
    s = re.sub(r'\s+', '-', s)
    s = re.sub(r'-{2,}', '-', s).strip('-')
    s = re.sub(r'[^A-Za-z0-9._-]+', '-', s)
    s = s[:maxlen].strip('-')
    return s

def main():
    sboms = os.environ.get("SBOMS", "sboms/spdx-lite.json,sboms/cyclonedx.json").split(",")
    comps = []
    for path in [s.strip() for s in sboms if s.strip()]:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        kind = detect(doc)
        if kind == "spdx":
            comps += parse_spdx(doc)
        elif kind == "cdx":
            comps += parse_cdx(doc)

    merged = {}
    for c in comps:
        key = ("purl", c.get("purl")) if c.get("purl") else ("nv", f"{(c.get('name') or '').lower()}@{(c.get('version') or '').lower()}")
        if key not in merged:
            merged[key] = c
        else:
            for fld in ("license", "url", "version"):
                if not merged[key].get(fld) and c.get(fld):
                    merged[key][fld] = c[fld]

    items = list(merged.values())
    matrix = {"include": []}
    for i, c in enumerate(items):
        base = c.get("purl") or c.get("name") or f"component-{i}"
        matrix["include"].append({
            "idx": i,
            "name": c.get("name") or "",
            "version": c.get("version") or "",
            "url": c.get("url") or "",
            "purl": c.get("purl") or "",
            "license": c.get("license") or "",
            "safe_name": slug(base)
        })
    matrix_json = json.dumps(matrix, ensure_ascii=False)
    title = os.environ.get("TITLE", "Open Source Notices")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
        out.write(f"matrix_json={matrix_json}\n")
        out.write(f"title={title}\n")

if __name__ == "__main__":
    main()

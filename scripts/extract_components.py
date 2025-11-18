import json
import argparse
import re

def norm(s):
    if s is None:
        return None
    s = str(s).strip()
    if not s or s.upper() in {"NOASSERTION", "NONE"}:
        return None
    return " ".join(s.split())

def detect_sbom_type(doc):
    if isinstance(doc, dict):
        if doc.get("bomFormat") == "CycloneDX":
            return "cdx"
        if "spdxVersion" in doc or "SPDXID" in doc or "packages" in doc:
            return "spdx"
    return "unknown"

def extract_from_spdx(doc):
    components = []
    for p in doc.get("packages", []):
        purl = None
        for ext_ref in p.get("externalRefs", []):
            if "purl" in (ext_ref.get("referenceType") or "").lower():
                purl = ext_ref.get("referenceLocator")
                break
        purl = norm(purl)
        name = None
        if purl:
            name = purl.split("/")[-1]
        else:
            name = norm(p.get("name"))
        version = norm(p.get("versionInfo")) or "latest"
        if not name:
            continue
        components.append({"component": name, "version": version, "purl": purl or "", "url": norm(p.get("downloadLocation")) or norm(p.get("homepage")) or ""})
    return components

def extract_from_cdx(doc):
    components = []
    for c in doc.get("components", []):
        purl = norm(c.get("purl"))
        name = None
        if purl:
            name = purl.split("/")[-1]
        else:
            name = norm(c.get("name"))
        version = norm(c.get("version")) or "latest"
        if not name:
            continue
        url = ""
        for extref in c.get("externalReferences", []):
            url_candidate = norm(extref.get("url"))
            if url_candidate:
                url = url_candidate
                break
        components.append({"component": name, "version": version, "purl": purl or "", "url": url})
    return components

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spdx", required=True)
    parser.add_argument("--cdx", required=True)
    args = parser.parse_args()

    components = []

    with open(args.spdx, "r", encoding="utf-8") as f:
        spdx_doc = json.load(f)
    if detect_sbom_type(spdx_doc) == "spdx":
        components.extend(extract_from_spdx(spdx_doc))

    with open(args.cdx, "r", encoding="utf-8") as f:
        cdx_doc = json.load(f)
    if detect_sbom_type(cdx_doc) == "cdx":
        components.extend(extract_from_cdx(cdx_doc))

    # Remove duplicates by component + version
    seen = set()
    unique_components = []
    for c in components:
        key = (c["component"], c["version"])
        if key not in seen:
            seen.add(key)
            unique_components.append(c)

    # Prepare matrix JSON
    matrix = {"include": []}
    for comp in unique_components:
        matrix["include"].append({
            "component": comp["component"],
            "version": comp["version"],
            "purl": comp["purl"],
            "url": comp["url"]
        })

    with open("matrix.json", "w", encoding="utf-8") as f:
        json.dump(matrix, f, indent=2)

if __name__ == "__main__":
    main()

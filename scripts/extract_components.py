import json
import argparse

def norm(s):
    if s is None:
        return None
    s = str(s).strip()
    if not s or s.upper() in {"NOASSERTION", "NONE"}:
        return None
    return " ".join(s.split())

def detect_sbom_type(doc):
    if isinstance(doc, dict):
        if doc.get("bomFormat") == "CycloneDX" or "components" in doc:
            return "cdx"
        if "spdxVersion" in doc or "SPDXID" in doc or "packages" in doc:
            return "spdx"
    return "unknown"

def extract_from_spdx(doc):
    components = []
    for p in doc.get("packages", []):
        url = norm(p.get("downloadLocation")) or norm(p.get("homepage")) or ""
        name = url.split("/")[-1] if url else norm(p.get("name"))
        version = norm(p.get("versionInfo")) or "latest"
        if not name:
            continue
        components.append({"component": name, "version": version, "url": url})
    return components

def extract_from_cdx(doc):
    components = []
    for c in doc.get("components", []):
        url = ""
        for extref in c.get("externalReferences", []):
            candidate = norm(extref.get("url"))
            if candidate:
                url = candidate
                break
        name = url.split("/")[-1] if url else norm(c.get("name"))
        version = norm(c.get("version")) or "latest"
        if not name:
            continue
        components.append({"component": name, "version": version, "url": url})
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

    # Deduplicate by name@version
    seen = set()
    unique_components = []
    for c in components:
        key = (c["component"], c["version"])
        if key not in seen:
            seen.add(key)
            unique_components.append(c)

    # Write plain array for matrix
    with open("matrix.json", "w", encoding="utf-8") as f:
        json.dump(unique_components, f, indent=2)

if __name__ == "__main__":
    main()

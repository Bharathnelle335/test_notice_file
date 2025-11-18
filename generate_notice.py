import os
import json
import glob
from spdx_tools.spdx.parser.parse_anything import parse_file as parse_spdx
from cyclonedx.parser.json import JsonParser as CycloneDXParser

SBOM_DIR = "./sboms"
NOTICE_FILE = "NOTICE.md"
COMPONENTS_FILE = "components.json"

def extract_spdx_components(path):
    doc = parse_spdx(path)
    data = []
    for pkg in doc.packages:
        name = pkg.name.split("/")[-1]
        url = getattr(pkg, "download_location", None) or (pkg.ext_document_refs[0].document_uri if pkg.ext_document_refs else "")
        copyright_text = getattr(pkg, "copyright_text", "") or ""
        license_expr = str(getattr(pkg, "license_concluded", "")) or ""

        data.append({
            "component": name,
            "version": getattr(pkg, "version", "") or "",
            "url": url,
            "copyright": copyright_text,
            "license": license_expr,
        })
    return data

def extract_cyclonedx_components(path):
    comp_list = []
    with open(path) as f:
        json_data = json.load(f)
    cx = CycloneDXParser(json_data)
    for comp in cx.bom.components:
        name = comp.name.split("/")[-1] if comp.name else ""
        url = comp.external_references[0].url if comp.external_references else ""
        license_id = comp.licenses[0].license.id if comp.licenses else ""
        comp_list.append({
            "component": name,
            "version": comp.version or "",
            "url": url,
            "copyright": getattr(comp, "copyright", "") or "",
            "license": license_id,
        })
    return comp_list

def unique_license_texts(licenses):
    # Mockup license texts - replace with real fetch if needed
    texts = {}
    for lic in set(licenses):
        texts[lic] = f"== Begin {lic} License Text ==\n...(license text)...\n== End {lic} =="
    return texts

def main():
    components = []
    for sbom_file in glob.glob(os.path.join(SBOM_DIR, "*.json")):
        try:
            if "spdx" in sbom_file.lower():
                components.extend(extract_spdx_components(sbom_file))
            else:
                components.extend(extract_cyclonedx_components(sbom_file))
        except Exception as e:
            print(f"Failed parsing {sbom_file}: {e}")

    # Save components for later ScanCode step
    with open(COMPONENTS_FILE, "w") as f:
        json.dump(components, f, indent=2)

    # Prepare NOTICE.md
    licenses = [c["license"] for c in components if c["license"]]
    license_texts = unique_license_texts(licenses)

    with open(NOTICE_FILE, "w") as f:
        f.write("# Combined NOTICE\n\n")
        f.write("| Component | Version | URL | Copyright | License |\n")
        f.write("|-----------|---------|-----|-----------|---------|\n")
        for c in components:
            f.write(f"| {c['component']} | {c['version']} | {c['url']} | {c['copyright']} | {c['license']} |\n")
        f.write("\n# License Texts\n\n")
        for lic, txt in license_texts.items():
            f.write(f"## {lic}\n{txt}\n\n")

    print(f"NOTICE.md generated with {len(components)} components.")

if __name__ == "__main__":
    main()

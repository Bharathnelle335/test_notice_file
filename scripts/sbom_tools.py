#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, glob, json, os, re, shlex, subprocess, sys, urllib.parse

HOSTS = ("github.com", "gitlab.com", "bitbucket.org")
SPDX_PATH = "sboms/spdx-lite.json"
CDX_PATH = "sboms/cyclonedx.json"

def ensure_dir(p): os.makedirs(p, exist_ok=True)
def load_json(path):
    if not os.path.exists(path): return None
    with open(path, "r", encoding="utf-8") as f: return json.load(f)

def is_git_host(url):
    if not url: return False
    u = url.strip().lower()
    return ("github.com" in u) or ("gitlab.com" in u) or ("bitbucket.org" in u) or u.startswith(("git://","git@","ssh://"))

def normalize_git_url(url):
    if not url: return None
    u = url.strip()
    if u.startswith("pkg:"): return None
    if not (u.startswith(("http://","https://","ssh://","git://","git@")) or is_git_host(u)): return None
    if u.startswith(("http://","https://")) and any(h in u for h in HOSTS):
        uu = u.rstrip("/")
        if not uu.endswith(".git"): uu += ".git"
        return uu
    return u

def last_segment(name):
    if not name: return None
    s = name
    for sep in ('/', ':'):
        if sep in s: s = s.split(sep)[-1]
    return s

def extract_from_purl(purl):
    if not purl: return (None, None, None)
    s = purl.strip()
    if s.startswith("pkg:"): s = s[4:]
    s = s.split('#', 1)[0].split('?', 1)[0]
    version = None
    base = s
    if '@' in s: base, version = s.rsplit('@', 1)
    component = urllib.parse.unquote(base.split('/')[-1])
    return (component, version, None)

def clean_version(ver):
    if not ver: return None
    v = str(ver).strip().lower()
    if v in {"", "unknown", "n/a", "na", "none"}: return None
    return str(ver).strip()

def pick_spdx_license_from_spdx(pkg): return (pkg.get("licenseConcluded") or pkg.get("licenseDeclared") or None)
def pick_spdx_license_from_cdx(comp):
    for lic in comp.get("licenses", []) or []:
        lobj = lic.get("license") or {}
        spdx_id = lobj.get("id")
        expr = lic.get("expression")
        if expr: return expr
        if spdx_id: return spdx_id
    return None

def _git_url_from_pkgish_locator(locator):
    if not locator: return None
    s = locator.strip()
    if not s.startswith("pkg:"): return None
    body = s[4:]
    body = body.split('#', 1)[0].split('?', 1)[0]
    if '@' in body: body, _ = body.rsplit('@', 1)
    parts = body.strip("/").split("/")
    if len(parts) < 3: return None
    host = owner = repo = None
    if parts[0] == "golang" and parts[1] in HOSTS and len(parts) >= 4:
        host, owner, repo = parts[1], parts[2], parts[3]
    elif parts[0] == "github" and len(parts) >= 3:
        host, owner, repo = "github.com", parts[1], parts[2]
    elif parts[0] in HOSTS and len(parts) >= 3:
        host, owner, repo = parts[0], parts[1], parts[2]
    if host and owner and repo:
        repo = repo.rstrip(".git")
        return f"https://{host}/{owner}/{repo}.git"
    return None

def best_git_url_from_spdx(pkg):
    if not pkg: return None
    u = normalize_git_url(pkg.get("downloadLocation") or "")
    if u: return u
    u = normalize_git_url(pkg.get("homepage") or "")
    if u: return u
    for ref in pkg.get("externalRefs", []) or []:
        rtype = (ref.get("referenceType") or ref.get("type") or "").lower()
        loc = ref.get("referenceLocator") or ref.get("locator") or ""
        if rtype in {"vcs","repository","scm"} or is_git_host(loc):
            u = normalize_git_url(loc)
            if u: return u
    for ref in pkg.get("externalRefs", []) or []:
        loc = ref.get("referenceLocator") or ref.get("locator") or ""
        if isinstance(loc, str) and loc.startswith("pkg:"):
            u = _git_url_from_pkgish_locator(loc)
            if u: return u
    return None

def best_git_url_from_cdx(comp, purl):
    if comp:
        for ref in comp.get("externalReferences", []) or []:
            rtype = (ref.get("type") or "").lower()
            url = ref.get("url") or ref.get("locator") or ""
            if rtype in {"vcs","repository","scm","source"} or is_git_host(url):
                u = normalize_git_url(url)
                if u: return u
        u = normalize_git_url(comp.get("repository") or "")
        if u: return u
        for ref in comp.get("externalReferences", []) or []:
            loc = ref.get("url") or ref.get("locator") or ""
            if isinstance(loc, str) and loc.startswith("pkg:"):
                u = _git_url_from_pkgish_locator(loc)
                if u: return u
    return None

def sanitize(s): return re.sub(r'[^A-Za-z0-9_.\-]+','-', (s or "")).strip('-') or "unknown"
def sh(cmd): print("+", cmd); return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def yaml_esc(s):
    if s is None: return '""'
    s = str(s)
    if re.search(r'[:#\-\[\]\{\},&\*?]|^\s|\s$', s):
        return '"' + s.replace('"','\\"') + '"'
    return s

# ---------------------------- Subcommands ----------------------------

def cmd_generate(_args):
    comps = []
    # CycloneDX
    data = load_json(CDX_PATH) or {}
    for c in data.get("components", []):
        purl = c.get("purl")
        name_p, ver_p, _ = extract_from_purl(purl) if purl else (None, None, None)
        name = name_p or last_segment(c.get("name"))
        version = clean_version(c.get("version") or ver_p)
        git_url = normalize_git_url(best_git_url_from_cdx(c, purl))
        license_sbom = pick_spdx_license_from_cdx(c)
        if name:
            comps.append({"component": name, "version": version, "git_url": git_url, "license": license_sbom})
    # SPDX
    data = load_json(SPDX_PATH) or {}
    for p in data.get("packages") or []:
        name = last_segment(p.get("name") or p.get("packageName"))
        version = clean_version(p.get("versionInfo"))
        purl = None
        for ref in p.get("externalRefs", []) or []:
            rtype = (ref.get("referenceType") or ref.get("type") or "").lower()
            loc = ref.get("referenceLocator") or ref.get("locator") or ""
            if rtype == "purl" and loc:
                purl = loc; break
        name_p, ver_p, _ = extract_from_purl(purl) if purl else (None, None, None)
        if name_p: name = name_p
        if not version: version = clean_version(ver_p)
        git_url = normalize_git_url(best_git_url_from_spdx(p))
        license_sbom = pick_spdx_license_from_spdx(p)
        if name:
            comps.append({"component": name, "version": version, "git_url": git_url, "license": license_sbom})

    # Merge by (component, version)
    merged = {}
    for c in comps:
        key = (c["component"], c.get("version") or "")
        prev = merged.get(key)
        if not prev: merged[key] = c
        else:
            if not prev.get("license") and c.get("license"): prev["license"] = c["license"]
            if not prev.get("git_url") and c.get("git_url"): prev["git_url"] = c["git_url"]

    result = list(merged.values())
    ensure_dir("artifacts")
    with open("artifacts/components.json", "w", encoding="utf-8") as f:
        json.dump({"components": result}, f, indent=2, ensure_ascii=False)
    print(f"Wrote artifacts/components.json with {len(result)} components.")

    # Keep and continue if git_url missing (partial + final outputs must include these)
    missing = [c["component"] for c in result if not c.get("git_url")]
    if missing:
        print("WARNING: No git_url found for components (will keep and continue): " + ", ".join(missing))

def cmd_split(_args):
    ensure_dir("artifacts")
    with open("artifacts/components.json", "r", encoding="utf-8") as f:
        comps = json.load(f).get("components", [])
    size = 5
    parts = [comps[i:i+size] for i in range(0, len(comps), size)]
    idxs = []
    for i, part in enumerate(parts):
        with open(f"artifacts/components_part_{i}.json", "w", encoding="utf-8") as f:
            json.dump({"components": part}, f, indent=2, ensure_ascii=False)
        idxs.append(str(i))
    go = os.environ.get("GITHUB_OUTPUT")
    if go:
        with open(go, "a") as gh:
            gh.write("parts=%s\n" % json.dumps(idxs))
            gh.write("part_count=%d\n" % len(parts))
    print(f"Split {len(comps)} components into {len(parts)} parts of up to {size}.")

def cmd_scan_part(args):
    part_index = str(args.part_index)
    scancode = args.scancode
    with open(f"artifacts/parts/components_part_{part_index}.json", "r", encoding="utf-8") as f:
        comps = json.load(f).get("components", [])
    ensure_dir(f"repos_part_{part_index}")
    ensure_dir(f"scancode_results_part_{part_index}")

    for item in comps:
        name = item.get("component")
        version = item.get("version")
        git_url = item.get("git_url")
        out_json = os.path.join(f"scancode_results_part_{part_index}", sanitize(name) + ".json")
        if not name or not git_url:
            with open(out_json, "w", encoding="utf-8") as f:
                json.dump({"files": [], "status": "skipped:no-git-url"}, f)
            continue
        dest = os.path.join(f"repos_part_{part_index}", sanitize(name) + (f"-{sanitize(version)}" if version else ""))
        if not os.path.exists(dest):
            if version:
                p = sh("git clone --depth 1 --branch %s %s %s" % (shlex.quote(str(version)), shlex.quote(git_url), shlex.quote(dest)))
                if p.returncode != 0:
                    print(p.stdout)
                    with open(out_json, "w", encoding="utf-8") as f:
                        json.dump({"files": [], "status": "skipped:clone-failed"}, f)
                    continue
            else:
                p = sh("git clone --depth 1 %s %s" % (shlex.quote(git_url), shlex.quote(dest)))
                if p.returncode != 0:
                    print(p.stdout)
                    with open(out_json, "w", encoding="utf-8") as f:
                        json.dump({"files": [], "status": "skipped:clone-failed"}, f)
                    continue
        cmd = (
            f"{shlex.quote(scancode)} --processes 4 "
            "--exclude .git --exclude vendor --exclude node_modules --exclude tests --exclude test --exclude docs "
            "--copyright --license --strip-root "
            f"--json-pp {shlex.quote(out_json)} {shlex.quote(dest)}"
        )
        p = sh(cmd)
        if p.returncode != 0: print(p.stdout)

def _resolve_base_components_path():
    # Robust: support either artifacts/components.json OR ./components.json
    candidates = ["artifacts/components.json", "components.json"]
    for p in candidates:
        if os.path.exists(p):
            return p
    raise FileNotFoundError("artifacts/components.json (or ./components.json) not found; did you download the 'components-json' artifact?")

def cmd_build_progress(_args):
    ensure_dir("artifacts")
    base_path = _resolve_base_components_path()
    with open(base_path, "r", encoding="utf-8") as f:
        base = json.load(f).get("components", [])
    merged = {}
    for fp in sorted(glob.glob("component*_part_*.json")):
        with open(fp,"r",encoding="utf-8") as f:
            data = json.load(f).get("components", [])
        for c in data:
            key = (c.get("component"), c.get("version") or "")
            merged[key] = c
    progress = []
    for comp in base:
        key = (comp.get("component"), comp.get("version") or "")
        if key in merged:
            progress.append(merged[key])

    with open("artifacts/component_copyrights_progress.json","w",encoding="utf-8") as f:
        json.dump({"components": progress}, f, indent=2, ensure_ascii=False)

    yl = ["components:"]
    for c in progress:
        name = c.get("component")
        version = c.get("version")
        url = c.get("git_url") or ""
        lic = c.get("license") or ""
        yl.append(" - component: " + yaml_esc(name))
        if version is not None: yl.append("   version: " + yaml_esc(version))
        yl.append("   url: " + yaml_esc(url))
        yl.append("   license: " + yaml_esc(lic))
        cps = c.get("copyrights", {}).get("unique_statements", []) or []
        if cps:
            yl.append("   copyrights:")
            for s in cps: yl.append("     - " + yaml_esc(s))
        else:
            yl.append("   copyrights: []")

    with open("artifacts/component_attribution_progress.yaml","w",encoding="utf-8") as f:
        f.write("\n".join(yl) + "\n")

    tl = []
    for c in progress:
        name = c.get("component") or ""
        version = c.get("version")
        url = c.get("git_url") or ""
        lic = c.get("license") or ""
        tl.append(f"Component: {name}")
        if version: tl.append(f"Version: {version}")
        tl.append(f"URL: {url}")
        tl.append(f"License: {lic}")
        tl.append("Copyrights:")
        cps = c.get("copyrights", {}).get("unique_statements", []) or []
        if cps:
            for s in cps: tl.append(f"- {s}")
        else:
            tl.append("- (none)")
        tl.append("")
    with open("artifacts/component_attribution_progress.txt","w",encoding="utf-8") as f:
        f.write("\n".join(tl).rstrip() + "\n")
    print("Progress: %d components merged so far." % len(progress))

def cmd_merge_final(_args):
    ensure_dir("artifacts")
    base_path = _resolve_base_components_path()
    with open(base_path,"r",encoding="utf-8") as f:
        all_components = json.load(f).get("components", [])
    merged = {}
    for fp in sorted(glob.glob("component*_part_*.json")):
        with open(fp,"r",encoding="utf-8") as f:
            data = json.load(f).get("components", [])
        for c in data:
            key = (c.get("component"), c.get("version") or "")
            merged[key] = c
    out = []
    for comp in all_components:
        key = (comp.get("component"), comp.get("version") or "")
        if key in merged:
            out.append(merged[key])
        else:
            out.append({
                "component": comp.get("component"),
                "version": comp.get("version"),
                "git_url": comp.get("git_url"),
                "license": comp.get("license"),
                "status": "scanned-or-missing",
                "copyrights":{ "unique_statements": [], "per_file": [] }
            })
    with open("artifacts/component_copyrights.json","w",encoding="utf-8") as f:
        json.dump({"components": out}, f, indent=2, ensure_ascii=False)
    print("Merged final copyrights for %d components." % len(out))

def cmd_build_final_attr(_args):
    base_path = _resolve_base_components_path()
    with open(base_path,"r",encoding="utf-8") as f:
        components = json.load(f).get("components", [])
    with open("artifacts/component_copyrights.json","r",encoding="utf-8") as f:
        agg = json.load(f).get("components", [])
    by_name = {c.get("component"): c for c in agg}

    yl = ["components:"]
    for comp in components:
        name = comp.get("component")
        version= comp.get("version")
        url = comp.get("git_url") or ""
        lic = comp.get("license") or ""
        yl.append(" - component: " + yaml_esc(name))
        if version is not None: yl.append("   version: " + yaml_esc(version))
        yl.append("   url: " + yaml_esc(url))
        yl.append("   license: " + yaml_esc(lic))
        cps = (by_name.get(name, {}) or {}).get("copyrights", {}).get("unique_statements", []) or []
        if cps:
            yl.append("   copyrights:")
            for c in cps: yl.append("     - " + yaml_esc(c))
        else:
            yl.append("   copyrights: []")
    ensure_dir("artifacts")
    with open("artifacts/component_attribution.yaml","w",encoding="utf-8") as f:
        f.write("\n".join(yl) + "\n")

    tl = []
    for comp in components:
        name = comp.get("component") or ""
        version = comp.get("version")
        url = comp.get("git_url") or ""
        lic = comp.get("license") or ""
        tl.append(f"Component: {name}")
        if version: tl.append(f"Version: {version}")
        tl.append(f"URL: {url}")
        tl.append(f"License: {lic}")
        tl.append("Copyrights:")
        cps = (by_name.get(name, {}) or {}).get("copyrights", {}).get("unique_statements", []) or []
        if cps:
            for s in cps: tl.append(f"- {s}")
        else:
            tl.append("- (none)")
        tl.append("")
    with open("artifacts/component_attribution.txt","w",encoding="utf-8") as f:
        f.write("\n".join(tl).rstrip() + "\n")
    print("Wrote final attribution YAML/TXT (order preserved).")

def main():
    ap = argparse.ArgumentParser(prog="sbom_tools.py", description="SBOM parsing and attribution tools")
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("generate")
    sp.add_parser("split")
    p_scan = sp.add_parser("scan-part"); p_scan.add_argument("--part-index", required=True); p_scan.add_argument("--scancode", required=True)
    p_agg = sp.add_parser("aggregate-part"); p_agg.add_argument("--part-index", required=True)
    p_attr = sp.add_parser("build-part-attr"); p_attr.add_argument("--part-index", required=True)
    sp.add_parser("build-progress")
    sp.add_parser("merge-final")
    sp.add_parser("build-final-attr")
    args = ap.parse_args()
    try:
        if args.cmd == "generate": cmd_generate(args)
        elif args.cmd == "split": cmd_split(args)
        elif args.cmd == "scan-part": cmd_scan_part(args)
        elif args.cmd == "aggregate-part": cmd_aggregate_part(args)
        elif args.cmd == "build-part-attr": cmd_build_part_attr(args)
        elif args.cmd == "build-progress": cmd_build_progress(args)
        elif args.cmd == "merge-final": cmd_merge_final(args)
        elif args.cmd == "build-final-attr": cmd_build_final_attr(args)
        else: raise SystemExit(f"Unknown command: {args.cmd}")
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

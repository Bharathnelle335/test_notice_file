import os, re, requests, json
from pathlib import Path
import subprocess

REQ_TIMEOUT = 45
name = os.environ["NAME"]
version = os.environ.get("VERSION")
purl = os.environ.get("PURL")
url = os.environ.get("URL")
safe = os.environ.get("SAFE_NAME", "component")

work = Path(".scancode_work") / safe
work.mkdir(parents=True, exist_ok=True)
fn = None

def get(url):
    r = requests.get(url, timeout=REQ_TIMEOUT)
    r.raise_for_status()
    return r

# Simplified for brevity:
# Handle common package managers here (npm, pypi, maven, nuget, gem, golang, and fallback GitHub)
# Same logic as in the matrix job of your provided workflow.

# Example: download tarball for npm
if purl and purl.startswith("pkg:npm/"):
    pkg = purl.split("/",2)[-1].split("@")[0]
    ver = version or (purl.split("@")[-1] if "@" in purl else None)
    meta = get(f"https://registry.npmjs.org/{pkg}/{ver or 'latest'}").json()
    tarball = meta["dist"]["tarball"]
    buf = get(tarball).content
    fn = work / f"{pkg}-{ver or 'latest'}.tgz"
    fn.write_bytes(buf)

# Add other ecosystems like in your workflow here...

if fn is None and url:
    m = re.match(r"https?://github\.com/([^/]+)/([^/?#]+)", url)
    if m:
        owner, repo = m.group(1), m.group(2)
        def try_codeload_zip(owner, repo, ref):
            u = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{ref}"
            r = requests.get(u, timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                zf = work / f"{repo}-{ref}.zip"
                zf.write_bytes(r.content)
                return zf
            return None
        def try_tag_zip(owner, repo, tag):
            u = f"https://codeload.github.com/{owner}/{repo}/zip/refs/tags/{tag}"
            r = requests.get(u, timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                zf = work / f"{repo}-{tag}.zip"
                zf.write_bytes(r.content)
                return zf
            return None
        if version and re.match(r"^[A-Za-z0-9._\-+/]+$", version):
            fn = try_tag_zip(owner, repo, version)
        if fn is None:
            try:
                api = f"https://api.github.com/repos/{owner}/{repo}"
                r = requests.get(api, timeout=REQ_TIMEOUT)
                if r.status_code == 200:
                    default_branch = r.json().get("default_branch")
                    if default_branch:
                        fn = try_codeload_zip(owner, repo, default_branch)
            except Exception:
                pass
        if fn is None:
            for ref in ("HEAD", "main", "master", "develop", "stable", "staging"):
                fn = try_codeload_zip(owner, repo, ref)
                if fn is not None:
                    break

# Extract if archive found
src_dir = work / "src"
src_dir.mkdir(parents=True, exist_ok=True)
if fn:
    if fn.suffix in {".tgz", ".gz", ".tar"}:
        import tarfile
        with tarfile.open(fn) as tf:
            tf.extractall(src_dir)
    elif fn.suffix == ".zip":
        import zipfile
        with zipfile.ZipFile(fn) as zf:
            zf.extractall(src_dir)

# Run ScanCode
scan_json = work / "scan.json"
subprocess.run([
    "scancode",
    "-cl",
    "--license-text",
    "--json-pp",
    str(scan_json),
    str(src_dir)
], check=True)

# Save meta.json
meta = {
    "name": name,
    "version": version or "",
    "url": url or "",
    "license": os.environ.get("LICENSE") or "",
    "purl": purl or "",
    "safe_name": safe
}
(meta_path := work / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

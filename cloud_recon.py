#!/usr/bin/env python3
"""
CloudRecon - Automated Cloud Asset Recon Tool
For authorized penetration testing and bug bounty only.
Author: CyberSpire
"""

import sys
import os
import re
import json
import time
import argparse
import subprocess
import threading
import urllib.request
import urllib.error
import urllib.parse
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# COLOR OUTPUT
# ─────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
  ╔═══════════════════════════════════════════════╗
  ║   ☁  CloudRecon  — Cloud Asset Recon Tool     ║
  ║   For authorized VAPT & bug bounty only       ║
  ╚═══════════════════════════════════════════════╝{C.RESET}
""")

def info(msg):    print(f"{C.BLUE}[*]{C.RESET} {msg}")
def success(msg): print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):    print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def fail(msg):    print(f"{C.RED}[-]{C.RESET} {msg}")
def section(msg): print(f"\n{C.BOLD}{C.CYAN}{'─'*50}\n  {msg}\n{'─'*50}{C.RESET}")

# ─────────────────────────────────────────────
# RESULTS STORE
# ─────────────────────────────────────────────

results = {
    "target": "",
    "timestamp": "",
    "s3_buckets": [],
    "gcp_buckets": [],
    "azure_blobs": [],
    "exposed_keys": [],
    "subdomains_cloud": [],
    "js_findings": [],
    "ssrf_params": [],
}

# ─────────────────────────────────────────────
# WORDLIST GENERATOR
# ─────────────────────────────────────────────

def generate_bucket_names(target):
    """Generate common S3/GCS/Azure bucket name permutations."""
    base = target.replace(".", "-").replace("_", "-").lower()
    parts = base.split("-")
    company = parts[0]

    suffixes = [
        "", "-dev", "-prod", "-staging", "-test", "-uat", "-qa",
        "-backup", "-backups", "-bak", "-assets", "-static", "-media",
        "-uploads", "-files", "-data", "-logs", "-internal", "-private",
        "-public", "-web", "-app", "-api", "-cdn", "-images", "-img",
        "-docs", "-reports", "-archive", "-releases", "-builds",
        "-config", "-secrets", "-keys", "-creds", "-db", "-database",
    ]

    names = set()
    for s in suffixes:
        names.add(f"{base}{s}")
        names.add(f"{company}{s}")

    return sorted(names)

# ─────────────────────────────────────────────
# HTTP HELPER
# ─────────────────────────────────────────────

def http_get(url, timeout=8, headers=None):
    """Simple HTTP GET. Returns (status_code, body, response_headers) or None on error."""
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; CloudRecon/1.0)")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192).decode("utf-8", errors="ignore")
            return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception:
        return None, "", {}

# ─────────────────────────────────────────────
# MODULE 1 — S3 BUCKET RECON
# ─────────────────────────────────────────────

def check_s3_bucket(name):
    """Check a single S3 bucket for public access (no creds needed)."""
    findings = []
    urls = [
        f"https://{name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{name}/",
    ]
    for url in urls:
        code, body, hdrs = http_get(url)
        if code is None:
            continue

        region = hdrs.get("x-amz-bucket-region", "unknown")

        if code == 200 and "<ListBucketResult" in body:
            # Try to count objects
            obj_count = body.count("<Key>")
            finding = {
                "bucket": name,
                "url": url,
                "status": "PUBLIC_READ + LISTING",
                "severity": "CRITICAL",
                "region": region,
                "objects_visible": obj_count,
            }
            findings.append(finding)
            success(f"[S3 CRITICAL] {name} — PUBLIC LISTING ({obj_count} objects visible) @ {url}")

            # Try write
            write_url = f"{url}cloudrecon-probe-{int(time.time())}.txt"
            wcode, _, _ = http_get(write_url)
            # Attempt PUT via subprocess if aws cli available
            _try_s3_write(name)

        elif code == 200:
            finding = {
                "bucket": name,
                "url": url,
                "status": "PUBLIC_READ",
                "severity": "HIGH",
                "region": region,
            }
            findings.append(finding)
            success(f"[S3 HIGH] {name} — PUBLIC READ @ {url}")

        elif code == 403:
            # Bucket exists but private
            finding = {
                "bucket": name,
                "url": url,
                "status": "EXISTS_PRIVATE",
                "severity": "INFO",
                "region": region,
            }
            findings.append(finding)
            info(f"[S3 INFO] {name} — exists but private (403) region={region}")
        break  # don't double-check both URL formats

    return findings

def _try_s3_write(bucket_name):
    """Attempt anonymous PUT via aws cli --no-sign-request."""
    try:
        result = subprocess.run(
            ["aws", "s3", "cp", "/dev/null",
             f"s3://{bucket_name}/cloudrecon-writetest.txt",
             "--no-sign-request", "--quiet"],
            capture_output=True, timeout=10
        )
        if result.returncode == 0:
            warn(f"[S3 CRITICAL] WRITE ACCESS confirmed on s3://{bucket_name}/")
    except Exception:
        pass

def run_s3_recon(target, wordlist=None, threads=20):
    section("MODULE 1 — AWS S3 Bucket Recon")
    names = wordlist if wordlist else generate_bucket_names(target)
    info(f"Testing {len(names)} bucket name permutations with {threads} threads...")

    all_findings = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_s3_bucket, n): n for n in names}
        for future in as_completed(futures):
            findings = future.result()
            all_findings.extend(findings)

    results["s3_buckets"] = all_findings
    info(f"S3 scan complete. Found {len(all_findings)} results.")

# ─────────────────────────────────────────────
# MODULE 2 — GCP Cloud Storage
# ─────────────────────────────────────────────

def check_gcp_bucket(name):
    url = f"https://storage.googleapis.com/{name}/"
    code, body, _ = http_get(url)
    if code == 200:
        obj_count = body.count("<Key>") + body.count("<name>")
        finding = {"bucket": name, "url": url, "status": "PUBLIC", "objects": obj_count}
        success(f"[GCP CRITICAL] gs://{name} — PUBLIC ({obj_count} objects)")
        return finding
    elif code == 403:
        info(f"[GCP INFO] gs://{name} — exists, private")
        return {"bucket": name, "url": url, "status": "EXISTS_PRIVATE"}
    return None

def run_gcp_recon(target, threads=15):
    section("MODULE 2 — GCP Cloud Storage Recon")
    names = generate_bucket_names(target)
    info(f"Testing {len(names)} GCP bucket names...")

    findings = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_gcp_bucket, n): n for n in names}
        for future in as_completed(futures):
            r = future.result()
            if r:
                findings.append(r)

    results["gcp_buckets"] = findings
    info(f"GCP scan complete. Found {len(findings)} results.")

# ─────────────────────────────────────────────
# MODULE 3 — Azure Blob Storage
# ─────────────────────────────────────────────

def check_azure_blob(storage_account, container=""):
    containers_to_try = [container] if container else [
        "$web", "public", "assets", "uploads", "static", "media",
        "backup", "files", "data", "images", "docs", "web"
    ]
    findings = []
    for cont in containers_to_try:
        url = f"https://{storage_account}.blob.core.windows.net/{cont}?restype=container&comp=list"
        code, body, _ = http_get(url)
        if code == 200 and "<EnumerationResults" in body:
            obj_count = body.count("<Name>")
            f = {
                "account": storage_account,
                "container": cont,
                "url": url,
                "status": "PUBLIC_LISTING",
                "objects": obj_count,
            }
            findings.append(f)
            success(f"[AZURE CRITICAL] {storage_account}/{cont} — PUBLIC LISTING ({obj_count} objects)")
        elif code == 200:
            f = {"account": storage_account, "container": cont, "url": url, "status": "PUBLIC_READ"}
            findings.append(f)
            success(f"[AZURE HIGH] {storage_account}/{cont} — PUBLIC READ")
    return findings

def run_azure_recon(target, threads=10):
    section("MODULE 3 — Azure Blob Storage Recon")
    names = generate_bucket_names(target)
    info(f"Testing {len(names)} Azure storage account names...")

    findings = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_azure_blob, n): n for n in names}
        for future in as_completed(futures):
            findings.extend(future.result())

    results["azure_blobs"] = findings
    info(f"Azure scan complete. Found {len(findings)} results.")

# ─────────────────────────────────────────────
# MODULE 4 — JS / Source Code Secret Scanning
# ─────────────────────────────────────────────

SECRET_PATTERNS = {
    "AWS Access Key":    r"(AKIA|ASIA|AROA|AIDA|ANPA)[A-Z0-9]{16}",
    "AWS Secret Key":    r"(?i)(aws_secret|secret_access_key|secretaccesskey)['\"\s:=]+([A-Za-z0-9/+=]{40})",
    "GCP API Key":       r"AIza[0-9A-Za-z-_]{35}",
    "Azure SAS Token":   r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=",
    "Azure Storage Key": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "S3 URL":            r"https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com",
    "Cognito Pool ID":   r"(us|eu|ap|ca|sa)-[a-z]+-\d_[A-Za-z0-9]{9}",
    "Cognito Identity":  r"(us|eu|ap|ca|sa)-[a-z]+-\d:[a-f0-9-]{36}",
    "Private Key":       r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Generic Secret":    r"(?i)(password|passwd|secret|token|api_key|apikey|auth_token)['\"\s:=]+['\"]([^'\"]{8,})['\"]",
}

def scan_js_content(url, content):
    findings = []
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            for m in matches[:3]:  # limit to 3 per pattern per file
                val = m if isinstance(m, str) else " | ".join(m)
                findings.append({
                    "type": name,
                    "value": val[:80],  # truncate
                    "source": url,
                })
                warn(f"[SECRET] {name} found in {url}: {val[:60]}...")
    return findings

def fetch_js_files(target_url, max_files=20):
    """Fetch main page and extract JS file URLs."""
    info(f"Fetching JS files from {target_url}...")
    code, body, _ = http_get(target_url)
    if not body:
        return []

    # Find all JS URLs
    js_urls = re.findall(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body)
    # Also find inline script content
    inline = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)

    abs_urls = []
    base = target_url.rstrip("/")
    parsed = urllib.parse.urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for u in js_urls[:max_files]:
        if u.startswith("http"):
            abs_urls.append(u)
        elif u.startswith("//"):
            abs_urls.append("https:" + u)
        elif u.startswith("/"):
            abs_urls.append(origin + u)
        else:
            abs_urls.append(base + "/" + u)

    return abs_urls, inline

def run_js_secret_scan(target_url):
    section("MODULE 4 — JS / Source Secret Scanning")
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    try:
        js_urls, inline_scripts = fetch_js_files(target_url)
    except Exception as e:
        warn(f"Could not fetch JS files: {e}")
        return

    all_findings = []

    # Scan inline scripts
    for i, script in enumerate(inline_scripts):
        findings = scan_js_content(f"{target_url}#inline-script-{i}", script)
        all_findings.extend(findings)

    # Scan external JS files
    info(f"Scanning {len(js_urls)} JS files for secrets...")
    def scan_url(u):
        code, body, _ = http_get(u, timeout=10)
        if body:
            return scan_js_content(u, body)
        return []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_url, u): u for u in js_urls}
        for future in as_completed(futures):
            all_findings.extend(future.result())

    results["js_findings"] = all_findings
    info(f"JS scan complete. Found {len(all_findings)} potential secrets.")

# ─────────────────────────────────────────────
# MODULE 5 — Subdomain Cloud Asset Detection
# ─────────────────────────────────────────────

CLOUD_CNAME_PATTERNS = {
    "AWS S3":         r"s3[.-]",
    "AWS CloudFront": r"cloudfront\.net",
    "AWS ELB":        r"elb\.amazonaws\.com",
    "AWS EC2":        r"compute\.amazonaws\.com",
    "AWS API GW":     r"execute-api\.[a-z0-9-]+\.amazonaws\.com",
    "GCP":            r"(appspot\.com|cloudfunctions\.net|run\.app|googleapis\.com)",
    "Azure":          r"(azurewebsites\.net|blob\.core\.windows\.net|azure\.com|cloudapp\.azure\.com)",
    "Cloudflare":     r"cloudflare",
    "Fastly":         r"fastly\.net",
    "Heroku":         r"herokussl\.com|herokuapp\.com",
    "Netlify":        r"netlify\.app|netlify\.com",
    "Vercel":         r"vercel\.app",
}

def check_subdomain_cloud(subdomain):
    try:
        answers = socket.getaddrinfo(subdomain, None)
        ip = answers[0][4][0]
    except Exception:
        return None

    # Try to get CNAME-like info via nslookup
    try:
        result = subprocess.run(
            ["nslookup", subdomain],
            capture_output=True, text=True, timeout=5
        )
        nslookup_out = result.stdout.lower()
    except Exception:
        nslookup_out = ""

    cloud_type = "Unknown"
    for ctype, pattern in CLOUD_CNAME_PATTERNS.items():
        if re.search(pattern, nslookup_out, re.IGNORECASE):
            cloud_type = ctype
            break

    return {"subdomain": subdomain, "ip": ip, "cloud": cloud_type}

def run_subdomain_cloud_check(target, subdomains=None):
    section("MODULE 5 — Subdomain Cloud Asset Detection")
    if not subdomains:
        # Generate common subdomain permutations
        base = target.lstrip("www.").split("/")[0]
        prefixes = [
            "www", "api", "dev", "staging", "prod", "app", "admin", "assets",
            "static", "media", "cdn", "s3", "storage", "files", "uploads",
            "backup", "internal", "portal", "dashboard", "auth", "login",
            "mail", "smtp", "vpn", "jenkins", "gitlab", "github", "jira",
        ]
        subdomains = [f"{p}.{base}" for p in prefixes]
        subdomains.append(base)

    info(f"Checking {len(subdomains)} subdomains for cloud assets...")
    found = []

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_subdomain_cloud, sd): sd for sd in subdomains}
        for future in as_completed(futures):
            r = future.result()
            if r:
                found.append(r)
                cloud_label = f"[{r['cloud']}]" if r['cloud'] != "Unknown" else ""
                msg = f"{r['subdomain']} → {r['ip']} {cloud_label}"
                if r["cloud"] != "Unknown":
                    success(msg)
                else:
                    info(msg)

    results["subdomains_cloud"] = found
    info(f"Subdomain check complete. Found {len(found)} live hosts.")

# ─────────────────────────────────────────────
# MODULE 6 — SSRF Parameter Detection
# ─────────────────────────────────────────────

SSRF_PARAMS = [
    "url", "redirect", "next", "src", "href", "image", "path", "dest",
    "target", "fetch", "proxy", "uri", "load", "resource", "link",
    "continue", "return", "returnTo", "checkout_url", "webhook",
    "callback", "forward", "service", "host", "endpoint", "data",
    "file", "open", "navigate", "domain", "site", "page", "ref",
    "feed", "to", "out", "view", "img_url", "imageurl", "logo",
]

def find_ssrf_params(target_url):
    section("MODULE 6 — SSRF Parameter Discovery")
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    info("Fetching app pages to find URL-like parameters...")
    code, body, _ = http_get(target_url)
    if not body:
        warn("Could not fetch target URL.")
        return

    found_params = []
    # Find form inputs and links with URL params
    for param in SSRF_PARAMS:
        patterns = [
            rf'name=["\']({param})["\']',
            rf'[?&]({param})=',
            rf'"({param})":\s*"https?://',
        ]
        for pat in patterns:
            if re.search(pat, body, re.IGNORECASE):
                found_params.append(param)
                warn(f"[SSRF CANDIDATE] Parameter '{param}' found in {target_url}")
                break

    results["ssrf_params"] = found_params
    info(f"Found {len(found_params)} potential SSRF parameters. Test these with: http://169.254.169.254/")

# ─────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_report(output_path):
    section("GENERATING REPORT")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = {**results, "timestamp": timestamp}

    # JSON report
    json_path = f"{output_path}/cloudrecon_{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    success(f"JSON report: {json_path}")

    # Markdown summary
    md_path = f"{output_path}/cloudrecon_{timestamp}.md"
    with open(md_path, "w") as f:
        f.write(f"# CloudRecon Report — {results['target']}\n")
        f.write(f"**Generated**: {timestamp}\n\n")
        f.write("---\n\n")

        def write_section(title, items, fields):
            f.write(f"## {title} ({len(items)} findings)\n\n")
            if not items:
                f.write("_No findings._\n\n")
                return
            for item in items:
                f.write("| Field | Value |\n|---|---|\n")
                for field in fields:
                    f.write(f"| {field} | {item.get(field, '-')} |\n")
                f.write("\n")

        write_section("🪣 S3 Buckets", results["s3_buckets"],
                      ["bucket", "url", "status", "severity", "region"])
        write_section("🪣 GCP Buckets", results["gcp_buckets"],
                      ["bucket", "url", "status"])
        write_section("🪣 Azure Blobs", results["azure_blobs"],
                      ["account", "container", "url", "status"])
        write_section("🔑 JS Secrets", results["js_findings"],
                      ["type", "value", "source"])
        write_section("🌐 Cloud Subdomains", results["subdomains_cloud"],
                      ["subdomain", "ip", "cloud"])

        if results["ssrf_params"]:
            f.write("## 🔗 SSRF Parameter Candidates\n\n")
            for p in results["ssrf_params"]:
                f.write(f"- `{p}`\n")
            f.write("\n")

    success(f"Markdown report: {md_path}")
    return md_path, json_path

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="CloudRecon — Automated Cloud Asset Recon (authorized testing only)"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target (e.g. targetcompany or targetcompany.com)")
    parser.add_argument("-u", "--url",
                        help="Target web app URL for JS scanning & SSRF detection")
    parser.add_argument("--modules", default="all",
                        help="Modules: all | s3 | gcp | azure | js | subdomains | ssrf (comma-separated)")
    parser.add_argument("--threads", type=int, default=20,
                        help="Number of threads (default: 20)")
    parser.add_argument("--wordlist",
                        help="Custom bucket names wordlist (one per line)")
    parser.add_argument("-o", "--output", default=".",
                        help="Output directory for reports")
    args = parser.parse_args()

    results["target"] = args.target
    os.makedirs(args.output, exist_ok=True)

    # Parse modules
    run_all = args.modules.lower() == "all"
    mods = [m.strip() for m in args.modules.split(",")] if not run_all else []

    # Load custom wordlist
    custom_wl = None
    if args.wordlist:
        with open(args.wordlist) as f:
            custom_wl = [l.strip() for l in f if l.strip()]
        info(f"Loaded {len(custom_wl)} names from custom wordlist.")

    target_url = args.url or f"https://{args.target}"

    print(f"\n{C.BOLD}Target  : {args.target}{C.RESET}")
    print(f"{C.BOLD}URL     : {target_url}{C.RESET}")
    print(f"{C.BOLD}Modules : {args.modules}{C.RESET}")
    print(f"{C.BOLD}Threads : {args.threads}{C.RESET}\n")
    print(f"{C.RED}{C.BOLD}[!] Ensure you have explicit authorization before running this tool.{C.RESET}\n")

    if run_all or "s3" in mods:
        run_s3_recon(args.target, wordlist=custom_wl, threads=args.threads)

    if run_all or "gcp" in mods:
        run_gcp_recon(args.target, threads=args.threads)

    if run_all or "azure" in mods:
        run_azure_recon(args.target, threads=args.threads)

    if run_all or "js" in mods:
        run_js_secret_scan(target_url)

    if run_all or "subdomains" in mods:
        run_subdomain_cloud_check(args.target)

    if run_all or "ssrf" in mods:
        find_ssrf_params(target_url)

    md_path, json_path = generate_report(args.output)

    section("SCAN COMPLETE")
    print(f"\n  {C.GREEN}S3 Buckets Found     : {len(results['s3_buckets'])}{C.RESET}")
    print(f"  {C.GREEN}GCP Buckets Found    : {len(results['gcp_buckets'])}{C.RESET}")
    print(f"  {C.GREEN}Azure Blobs Found    : {len(results['azure_blobs'])}{C.RESET}")
    print(f"  {C.GREEN}JS Secrets Found     : {len(results['js_findings'])}{C.RESET}")
    print(f"  {C.GREEN}Cloud Subdomains     : {len(results['subdomains_cloud'])}{C.RESET}")
    print(f"  {C.GREEN}SSRF Params Found    : {len(results['ssrf_params'])}{C.RESET}")
    print(f"\n  Reports saved to: {args.output}\n")


if __name__ == "__main__":
    main()

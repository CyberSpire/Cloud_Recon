# ☁️ CloudRecon — Automated Cloud Asset Recon Tool

> For authorized penetration testing and bug bounty research only.

---

## 📦 Requirements

- Python 3.8+
- No external dependencies (uses stdlib only)
- Optional: `aws` CLI installed for write-access confirmation on S3

---

## 🚀 Usage

<img width="1189" height="310" alt="CLOUD RECON HELP" src="https://github.com/user-attachments/assets/88741b38-64d3-43da-abc5-b2d99c7b6478" />

```bash
# Run all modules against a target
python3 cloud_recon.py -t targetcompany -u https://targetcompany.com

# Run only S3 + JS scanning
python3 cloud_recon.py -t targetcompany -u https://targetcompany.com --modules s3,js

# Use custom bucket wordlist
python3 cloud_recon.py -t targetcompany --wordlist my_buckets.txt --modules s3

# Save report to specific folder
python3 cloud_recon.py -t targetcompany -u https://targetcompany.com -o ./reports

# Increase threads for faster scanning
python3 cloud_recon.py -t targetcompany --threads 40
```
<img width="1277" height="651" alt="CLOUD RECON RESULT" src="https://github.com/user-attachments/assets/5892cd9d-e337-4e25-b70b-9dd95324bfa8" />

<img width="928" height="660" alt="CLOUD RECON RESULT 2" src="https://github.com/user-attachments/assets/a8fa63cc-e5e9-4439-b096-790ff30ac46a" />

---

## 🔍 Modules

| Module | Flag | What it does |
|---|---|---|
| S3 Recon | `s3` | Tests ~35 bucket permutations for public read/write/listing |
| GCP Recon | `gcp` | Tests GCS bucket names for public access |
| Azure Recon | `azure` | Tests Azure storage account + containers |
| JS Secrets | `js` | Fetches JS files, scans for AWS keys, GCP keys, tokens |
| Subdomains | `subdomains` | Resolves 30+ subdomain guesses, detects cloud provider |
| SSRF Params | `ssrf` | Finds URL-like parameters in app for SSRF testing |

---

## 📄 Output

- `cloudrecon_TIMESTAMP.json` — full structured results
- `cloudrecon_TIMESTAMP.md` — Notion/markdown summary table

---

## ⚠️ Legal

Only use against targets you have explicit written authorization to test.

# MailAudit

🛡️ **MailAudit** is a Bash-based tool that audits the security posture of mail domains.  
It checks DNS, MX records, TLS, DANE, and policy configurations (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, CAA, DNSSEC) to ensure domains are hardened against spoofing, downgrade attacks, and misconfigurations.

---

## ✨ Features

- 🔍 Resolve MX records for a domain
- 🌐 Detect cloud/hosted MX (Microsoft 365, Google Workspace, etc.) and skip redundant checks
- 📡 Port & TLS checks:
  - 25 (SMTP)
  - 465 (SMTPS)
  - 587 (Submission, if open)
  - 993 (IMAPS)
- 🔑 Validate **DANE/TLSA** records
- 🔒 Detect TLS protocol support (1.0 → 1.3)
- 📜 Parse and validate X.509 certificates
- 📨 Check **SPF**, **DMARC** (DKIM is inferred via keys), **ARC**
- 📑 Fetch and validate **MTA-STS** policies (handles CRLF/BOM issues)
- 📊 Check **TLS-RPT**, **BIMI**, **CAA**, and **DNSSEC**
- 🚫 Highlight weak, missing, or legacy configurations
- ⚡ Parallel mode for faster scans

---

## ⚡ Requirements

- `bash` (>= 3.0, tested on macOS’s Bash 3 and GNU Bash 4+)
- `dig` (bind-utils / dnsutils)
- `curl`
- `openssl`
- `nc` or `ncat`

⚠️ **Note:** MailAudit has been tested on **macOS** and **Ubuntu/Debian**.  
It should also work on other Linux distros, but you may need to install the required dependencies manually.

On Debian/Ubuntu:

```bash
sudo apt install dnsutils curl openssl netcat
```

On RHEL/CentOS:

```bash
sudo yum install bind-utils curl openssl nmap-ncat
```

---

## 🚀 Usage

Clone the repo:

```bash
git clone https://github.com/lulzkiller666/MailAudit.git
cd MailAudit
chmod +x MailAudit.sh
```

Run a simple scan against a domain (auto-detect MX):

```bash
./MailAudit.sh example.com
```

Run against a domain and its MX (explicit):

```bash
./MailAudit.sh -D example.com --mx
```

Run directly against a host:

```bash
./MailAudit.sh -H mail.example.com
```

Run with parallel scanning enabled:

```bash
./MailAudit.sh example.com --parallel
```

---

### Example output

<img width="825" height="913" alt="image" src="https://github.com/user-attachments/assets/d10cde85-d179-4b14-bb47-664bf47a2ce9" />

---

## 📖 References

- [NIST SP 800-177: Trustworthy Email](https://csrc.nist.gov/publications/detail/sp/800-177/rev-1/final)  
- [NIST SP 800-52r2: TLS Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)  
- [RFC 8461: SMTP MTA Strict Transport Security (MTA-STS)](https://www.rfc-editor.org/rfc/rfc8461)  
- [RFC 8460: SMTP TLS Reporting (TLS-RPT)](https://www.rfc-editor.org/rfc/rfc8460)

---

## 📜 License

MIT

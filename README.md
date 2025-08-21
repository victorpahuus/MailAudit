# MailAudit

🛡️ **MailAudit** is a Bash-based tool that audits the security posture of mail domains.  
It checks DNS, MX records, TLS, DANE, and policy configurations (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, CAA, DNSSEC) to ensure domains are hardened against spoofing, downgrade attacks, and misconfigurations.

---

## ✨ Features

- 🔍 Resolve MX records for a domain
- 🌐 Detect cloud/hosted MX (Microsoft, Google, etc.) and skip redundant tests
- 📡 Port & TLS checks:
  - 25 (SMTP)
  - 465 (SMTPS)
  - 587 (Submission)
  - 993 (IMAPS)
- 🔑 Validate **DANE/TLSA** records
- 🔒 Detect TLS protocol support (1.0 → 1.3)
- 📜 Parse and validate X.509 certificates
- 📨 Check **SPF**, **DKIM**, **DMARC**
- 📑 Fetch and validate **MTA-STS** policies (handles CRLF/BOM issues)
- 📊 Check **TLS-RPT**, **BIMI**, **CAA**, and **DNSSEC**
- 🚫 Highlight weak or missing configurations

---

## ⚡ Requirements

- `bash` (>= 4.0)
- `dig` (bind-utils / dnsutils)
- `curl`
- `openssl`
- `nc` or `ncat`

⚠️ **Note:** MailAudit has only been tested on **osx** so far.  
It should also work on Linux, but you may need to install the required dependencies manually.

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
git clone https://github.com/<youruser>/MailAudit.git
cd MailAudit
chmod +x mailaudit.sh
```

Run a scan:

```bash
./mailaudit.sh example.com
```

Example output:

<img width="825" height="913" alt="image" src="https://github.com/user-attachments/assets/d10cde85-d179-4b14-bb47-664bf47a2ce9" />


## 📖 References

- [NIST SP 800-177: Trustworthy Email](https://csrc.nist.gov/publications/detail/sp/800-177/rev-1/final)  
- [NIST SP 800-52r2: TLS Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)  
- [RFC 8461: SMTP MTA Strict Transport Security (MTA-STS)](https://www.rfc-editor.org/rfc/rfc8461)  
- [RFC 8460: SMTP TLS Reporting (TLS-RPT)](https://www.rfc-editor.org/rfc/rfc8460)

---

## 📜 License

MIT

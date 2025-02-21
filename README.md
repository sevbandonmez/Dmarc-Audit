# DMARC Audit Tool

A comprehensive security auditing tool to analyze DMARC, SPF, and DKIM configurations.

Designed to quickly audit and capture screenshots for penetration testing and security assessments.

![DMARC Audit Tool Screenshot](https://github.com/user-attachments/assets/6e8e64f7-18d0-443d-b7cb-a1e69b2b82a4)
![SPF & DKIM Check Screenshot](https://github.com/user-attachments/assets/2efaa269-c11c-487d-9144-653bc364d910)

## Features

- **DMARC Record Analysis** - Verifies and evaluates DMARC policies.
- **SPF Record Validation** - Ensures SPF records are properly configured.
- **DKIM Configuration Checks** - Examines DKIM selectors and keys.
- **MX Record Security Validation** - Checks mail exchange records for security flaws.
- **SSL/TLS Certificate Analysis** - Assesses SSL/TLS configurations.
- **RSA Key Strength Verification** - Analyzes the strength of cryptographic keys.
- **Detailed Security Reporting** - Provides in-depth audit reports.
- **Multiple Output Formats** - Supports JSON, CSV, and standard output formats.

---

## Installation

### Clone the Repository
```bash
git clone https://github.com/sevbandonmez/dmarc-audit.git
cd dmarc-audit
```

### Install Dependencies
```bash
pip install -r requirements.txt
python3 setup.py install
pip install -e .
```

---

## Usage

### Basic Scan
```bash
python -m dmarc_audit example.com
```

### Detailed Report
```bash
python -m dmarc_audit example.com --detailed
```

### Output Formats
```bash
python -m dmarc_audit example.com --format json
python -m dmarc_audit example.com --format csv
```

### Custom DKIM Selector
```bash
python -m dmarc_audit example.com --dkim-selector myselector
```

---

## License

This project is licensed under the **MIT License**. See the `LICENSE` file for more details.

## Author

**Sevban Dönmez**  
GitHub: [@sevbandonmez](https://github.com/sevbandonmez)


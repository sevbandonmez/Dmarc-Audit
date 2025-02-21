# DMARC Audit Tool

A comprehensive security audit tool for analyzing DMARC, SPF, and DKIM configurations.

## Features

- Complete DMARC record analysis
- SPF record validation
- DKIM configuration checks
- MX record security validation
- SSL/TLS certificate analysis
- RSA key strength verification
- Detailed security reporting
- Multiple output formats (JSON, CSV)

## Installation

git clone https://github.com/sevbandonmez/dmarc-audit.git
cd dmarc-audit
python3 setup.py install
pip install -e .
pip install -r requirements.txt

### Basic Usage

python -m dmarc_audit example.com

### Detailed Report

python -m dmarc_audit example.com --detailed    

### Output Formats

python -m dmarc_audit example.com --format json
python -m dmarc_audit example.com --format csv      

### Custom DKIM selector

python -m dmarc_audit example.com --dkim-selector myselector

## Installation

bash
git clone https://github.com/sevbandonmez/dmarc-audit.git
cd dmarc-audit
pip install -r requirements.txt

## Usage

python dmarc_audit.py example.com
python dmarc_audit.py example.com --detailed
python dmarc_audit.py example.com --format json

## License

MIT License - See LICENSE file for details

## Author

Sevban Dönmez
- GitHub: [@sevbandonmez](https://github.com/sevbandonmez)
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="dmarc-audit",
    version="1.0.0",
    author="Sevban Dönmez",
    description="A comprehensive DMARC, SPF and DKIM security analyzer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "dnspython",
        "rich",
        "colorama",
        "pyfiglet"
    ],
    entry_points={
        "console_scripts": [
            "dmarc-audit=dmarc_audit.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
) 
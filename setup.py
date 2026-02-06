#!/usr/bin/env python3

#Setup script for ButtF

from setuptools import setup, find_packages
import os

#Read long description from README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

#Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="buttf",
    version="1.0.0",
    author="ButtF Security Tool",
    author_email="contact@s0lairworks@gmail.com",
    description="Backend Misconfiguration & Logic Flaw Exploitation Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/s0lairworks/ButtF",
    project_urls={
        "Bug Tracker": "https://github.com/s0lairworks/ButtF/issues",
        "Documentation": "https://github.com/s0lairworks/ButtF#readme",
        "Source Code": "https://github.com/s0lairworks/ButtF",
        "Changelog": "https://github.com/s0lairworks/ButtF/blob/main/CHANGELOG.md",
    },
    packages=find_packages(),
    py_modules=["buttf", "threat_analyzer"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "pylint>=2.12.0",
            "mypy>=0.950",
        ],
        "security": [
            "safety>=2.0.0",
            "bandit>=1.7.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "buttf=buttf:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt", "*.json"],
    },
    keywords=[
        "security",
        "pentesting",
        "vulnerability-scanner",
        "security-testing",
        "web-security",
        "backend-security",
        "logic-flaws",
        "misconfiguration",
        "cve-detection",
        "security-audit",
    ],
    license="MIT",
    zip_safe=False,
)

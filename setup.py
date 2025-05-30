"""
Setup configuration for API Hunter
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = []
with open('requirements.txt', 'r') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="api-hunter",
    version="1.0.0",
    author="API Hunter Team",
    author_email="contact@apihunter.io",
    description="Advanced Bug Bounty Tool for API Security Testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/api-hunter/api-hunter",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-asyncio>=0.21.1",
            "black>=23.11.0",
            "flake8>=6.1.0",
            "mypy>=1.7.0",
        ],
        "docs": [
            "sphinx>=7.1.0",
            "sphinx-rtd-theme>=1.3.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "api-hunter=api_hunter.main:cli",
            "apihunter=api_hunter.main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "api_hunter": [
            "config/*.yaml",
            "templates/*.html",
            "wordlists/*.txt",
        ],
    },
    keywords="security api testing bug-bounty penetration-testing vulnerability-scanner",
    project_urls={
        "Bug Reports": "https://github.com/api-hunter/api-hunter/issues",
        "Source": "https://github.com/api-hunter/api-hunter",
        "Documentation": "https://api-hunter.readthedocs.io/",
    },
)

"""
API Hunter - Advanced Bug Bounty Tool for API Security Testing

A comprehensive, AI-powered bug bounty hunting tool specifically designed for
discovering and exploiting vulnerabilities in modern APIs.
"""

__version__ = "1.0.0"
__author__ = "API Hunter Team"
__email__ = "contact@apihunter.io"
__license__ = "MIT"

from api_hunter.core.config import Config
from api_hunter.core.logger import get_logger

# Core exports
__all__ = [
    "Config",
    "get_logger",
    "__version__",
]

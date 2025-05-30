"""
Wordlist manager for fuzzing.
"""

import logging
from typing import Dict, List, Optional, Any

from ..core.config import Config

logger = logging.getLogger(__name__)


class WordlistManager:
    """Manage wordlists for fuzzing."""

    def __init__(self, config: Config):
        self.config = config

    def get_wordlist(self, category: str) -> List[str]:
        """Get wordlist for category."""
        # Basic wordlist - in full implementation would load from files
        return ["test", "admin", "user", "password", "secret"]

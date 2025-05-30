"""
Base Discoverer Abstract Class

Provides the foundation for all API discovery implementations.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import asyncio
import httpx
from urllib.parse import urljoin, urlparse


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered API endpoint"""
    url: str
    method: str
    parameters: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    schema_info: Optional[Dict[str, Any]] = None
    auth_required: bool = False
    description: Optional[str] = None


@dataclass
class DiscoveryResult:
    """Results from a discovery scan"""
    endpoints: List[DiscoveredEndpoint]
    schemas: List[Dict[str, Any]]
    technologies: List[str]
    documentation_urls: List[str]
    errors: List[str]


class BaseDiscoverer(ABC):
    """Abstract base class for all API discoverers"""

    def __init__(self, client: httpx.AsyncClient, base_url: str):
        self.client = client
        self.base_url = base_url.rstrip('/')
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.errors: List[str] = []

    @abstractmethod
    async def discover(self) -> DiscoveryResult:
        """
        Perform API discovery and return results
        
        Returns:
            DiscoveryResult: Comprehensive discovery results
        """
        pass

    @abstractmethod
    def get_discovery_type(self) -> str:
        """Return the type of discovery this class performs"""
        pass

    async def _make_request(
            self,
            path: str,
            method: str = "GET",
            **kwargs
    ) -> Optional[httpx.Response]:
        """
        Make an HTTP request with error handling
        
        Args:
            path: URL path to request
            method: HTTP method
            **kwargs: Additional arguments for httpx
        
        Returns:
            Response object or None if request failed
        """
        try:
            url = urljoin(self.base_url, path)
            response = await self.client.request(method, url, **kwargs)
            return response
        except Exception as e:
            self.errors.append(f"Request failed for {path}: {str(e)}")
            return None

    def _is_valid_url(self, url: str) -> bool:
        """Validate if a URL is properly formatted"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def _normalize_endpoint(self, endpoint: DiscoveredEndpoint) -> DiscoveredEndpoint:
        """Normalize and validate discovered endpoint"""
        # Ensure URL is absolute
        if not self._is_valid_url(endpoint.url):
            endpoint.url = urljoin(self.base_url, endpoint.url)

        # Normalize method
        endpoint.method = endpoint.method.upper()

        return endpoint

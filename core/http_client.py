"""
Advanced HTTP client for API Hunter with async support, rate limiting, and retries.
"""

import asyncio
import time
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import httpx
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from api_hunter.core.logger import get_component_logger

logger = get_component_logger("http_client")


@dataclass
class RequestConfig:
    """Configuration for HTTP requests."""
    timeout: int = 30
    verify_ssl: bool = False
    allow_redirects: bool = True
    max_redirects: int = 10
    proxy: Optional[str] = None
    proxy_auth: Optional[tuple] = None
    headers: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_second: float = 10.0
    burst_size: int = 20
    backoff_factor: float = 0.5
    max_backoff: float = 60.0


@dataclass
class RetryConfig:
    """Retry configuration."""
    max_retries: int = 3
    backoff_factor: float = 0.3
    retry_on_status: List[int] = None

    def __post_init__(self):
        if self.retry_on_status is None:
            self.retry_on_status = [408, 429, 500, 502, 503, 504]


class TokenBucket:
    """Token bucket implementation for rate limiting."""

    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_update = time.time()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = time.time()
            # Add tokens based on elapsed time
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens >= 1:
                self.tokens -= 1
                return

            # Wait for next token
            wait_time = (1 - self.tokens) / self.rate
            await asyncio.sleep(wait_time)
            self.tokens = 0


class AsyncHTTPClient:
    """Asynchronous HTTP client with advanced features."""

    def __init__(
            self,
            request_config: RequestConfig = None,
            rate_limit_config: RateLimitConfig = None,
            retry_config: RetryConfig = None
    ):
        self.request_config = request_config or RequestConfig()
        self.rate_limit_config = rate_limit_config or RateLimitConfig()
        self.retry_config = retry_config or RetryConfig()

        # Initialize rate limiter
        self.rate_limiter = TokenBucket(
            self.rate_limit_config.requests_per_second,
            self.rate_limit_config.burst_size
        )

        # HTTP client configuration
        self.client_config = {
            "timeout": httpx.Timeout(self.request_config.timeout),
            "verify": self.request_config.verify_ssl,
            "follow_redirects": self.request_config.allow_redirects,
            "max_redirects": self.request_config.max_redirects,
        }

        if self.request_config.proxy:
            self.client_config["proxies"] = {
                "http://": self.request_config.proxy,
                "https://": self.request_config.proxy,
            }

        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        """Async context manager entry."""
        self._client = httpx.AsyncClient(**self.client_config)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()

    async def request(
            self,
            method: str,
            url: str,
            headers: Optional[Dict[str, str]] = None,
            data: Optional[Union[str, bytes, Dict]] = None,
            json_data: Optional[Dict] = None,
            params: Optional[Dict[str, str]] = None,
            **kwargs
    ) -> httpx.Response:
        """
        Make an HTTP request with rate limiting and retries.
        
        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            data: Request data
            json_data: JSON data
            params: URL parameters
            **kwargs: Additional request arguments
            
        Returns:
            HTTP response object
        """
        # Rate limiting
        await self.rate_limiter.acquire()

        # Prepare headers
        request_headers = self.request_config.headers.copy() if self.request_config.headers else {}
        if headers:
            request_headers.update(headers)

        # Prepare request arguments
        request_kwargs = {
            "method": method,
            "url": url,
            "headers": request_headers,
            "params": params,
            **kwargs
        }

        if json_data:
            request_kwargs["json"] = json_data
        elif data:
            request_kwargs["data"] = data

        # Retry logic
        last_exception = None
        for attempt in range(self.retry_config.max_retries + 1):
            try:
                logger.debug(f"Request attempt {attempt + 1}: {method} {url}")
                response = await self._client.request(**request_kwargs)

                # Check if we should retry based on status code
                if (response.status_code not in self.retry_config.retry_on_status or
                        attempt == self.retry_config.max_retries):
                    return response

                # Calculate backoff time
                backoff_time = (self.retry_config.backoff_factor * (2 ** attempt))
                backoff_time = min(backoff_time, self.rate_limit_config.max_backoff)

                logger.warning(f"Request failed with status {response.status_code}, retrying in {backoff_time}s")
                await asyncio.sleep(backoff_time)

            except Exception as e:
                last_exception = e
                if attempt == self.retry_config.max_retries:
                    break

                backoff_time = (self.retry_config.backoff_factor * (2 ** attempt))
                backoff_time = min(backoff_time, self.rate_limit_config.max_backoff)

                logger.warning(f"Request failed with exception: {e}, retrying in {backoff_time}s")
                await asyncio.sleep(backoff_time)

        if last_exception:
            raise last_exception

        # This should not be reached, but just in case
        raise Exception("All retry attempts failed")

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Make a GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Make a POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> httpx.Response:
        """Make a PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> httpx.Response:
        """Make a PATCH request."""
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """Make a DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> httpx.Response:
        """Make a HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> httpx.Response:
        """Make an OPTIONS request."""
        return await self.request("OPTIONS", url, **kwargs)


class SyncHTTPClient:
    """Synchronous HTTP client for compatibility."""

    def __init__(
            self,
            request_config: RequestConfig = None,
            retry_config: RetryConfig = None
    ):
        self.request_config = request_config or RequestConfig()
        self.retry_config = retry_config or RetryConfig()

        # Create session
        self.session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=self.retry_config.max_retries,
            status_forcelist=self.retry_config.retry_on_status,
            backoff_factor=self.retry_config.backoff_factor,
            respect_retry_after_header=True
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Configure session
        self.session.verify = self.request_config.verify_ssl

        if self.request_config.headers:
            self.session.headers.update(self.request_config.headers)

        if self.request_config.proxy:
            self.session.proxies = {
                "http": self.request_config.proxy,
                "https": self.request_config.proxy,
            }

    def request(
            self,
            method: str,
            url: str,
            **kwargs
    ) -> requests.Response:
        """Make an HTTP request."""
        kwargs.setdefault("timeout", self.request_config.timeout)
        kwargs.setdefault("allow_redirects", self.request_config.allow_redirects)

        return self.session.request(method, url, **kwargs)

    def get(self, url: str, **kwargs) -> requests.Response:
        """Make a GET request."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """Make a POST request."""
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> requests.Response:
        """Make a PUT request."""
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs) -> requests.Response:
        """Make a PATCH request."""
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response:
        """Make a DELETE request."""
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        """Make a HEAD request."""
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        """Make an OPTIONS request."""
        return self.request("OPTIONS", url, **kwargs)

    def close(self):
        """Close the session."""
        self.session.close()


def create_http_client(
        async_client: bool = True,
        request_config: RequestConfig = None,
        rate_limit_config: RateLimitConfig = None,
        retry_config: RetryConfig = None
) -> Union[AsyncHTTPClient, SyncHTTPClient]:
    """
    Factory function to create HTTP client.
    
    Args:
        async_client: Whether to create async client
        request_config: Request configuration
        rate_limit_config: Rate limiting configuration (async only)
        retry_config: Retry configuration
        
    Returns:
        HTTP client instance
    """
    if async_client:
        return AsyncHTTPClient(request_config, rate_limit_config, retry_config)
    else:
        return SyncHTTPClient(request_config, retry_config)


class HTTPClient:
    """
    Unified HTTP client that automatically adapts to sync/async context.
    
    This is a compatibility wrapper that provides a unified interface
    and automatically uses the appropriate underlying client.
    """

    def __init__(self, config=None):
        self.config = config
        self.request_config = RequestConfig()
        self.rate_limit_config = RateLimitConfig()
        self.retry_config = RetryConfig()

        # Create async client
        self._async_client = AsyncHTTPClient(
            self.request_config,
            self.rate_limit_config,
            self.retry_config
        )

        # Create sync client
        self._sync_client = SyncHTTPClient(
            self.request_config,
            self.retry_config
        )

    async def request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make an HTTP request (async version)."""
        async with self._async_client as client:
            response = await client.request(method, url, **kwargs)
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
                'content': response.content,
                'url': str(response.url),
                'response_time': getattr(response, 'elapsed', 0)
            }

    def request_sync(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make an HTTP request (sync version)."""
        response = self._sync_client.request(method, url, **kwargs)
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'body': response.text,
            'content': response.content,
            'url': response.url,
            'response_time': response.elapsed.total_seconds() if response.elapsed else 0
        }

    async def get(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make a GET request."""
        return await self.request('GET', url, **kwargs)

    async def post(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make a POST request."""
        return await self.request('POST', url, **kwargs)

    async def put(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make a PUT request."""
        return await self.request('PUT', url, **kwargs)

    async def patch(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make a PATCH request."""
        return await self.request('PATCH', url, **kwargs)

    async def delete(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make a DELETE request."""
        return await self.request('DELETE', url, **kwargs)

    async def head(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make a HEAD request."""
        return await self.request('HEAD', url, **kwargs)

    async def options(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make an OPTIONS request."""
        return await self.request('OPTIONS', url, **kwargs)

    async def close(self):
        """Close the client."""
        # AsyncHTTPClient uses context manager, so nothing to do here
        self._sync_client.close()

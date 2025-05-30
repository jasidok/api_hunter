"""
REST API Discovery Module

Discovers REST API endpoints through pattern recognition, common conventions,
and intelligent path traversal.
"""

import re
import asyncio
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass
import httpx

from .base_discoverer import BaseDiscoverer, DiscoveredEndpoint, DiscoveryResult


@dataclass
class PathPattern:
    """Represents a discovered path pattern"""
    pattern: str
    methods: List[str]
    params: List[str]
    confidence: float


class RESTDiscoverer(BaseDiscoverer):
    """Discovers REST APIs through pattern recognition and path traversal"""

    # Common REST API patterns
    COMMON_API_PATHS = [
        '/api',
        '/api/',
        '/v1',
        '/v2',
        '/v3',
        '/api/v1',
        '/api/v2',
        '/api/v3',
        '/rest',
        '/rest/',
        '/services',
        '/service',
        '/public',
        '/internal',
        '/admin',
        '/users',
        '/user',
        '/auth',
        '/login',
        '/register',
        '/health',
        '/status',
        '/ping',
        '/info',
        '/debug',
        '/metrics',
        '/config',
        '/settings',
    ]

    # Common resource names for REST APIs
    COMMON_RESOURCES = [
        'users', 'user', 'accounts', 'account',
        'products', 'product', 'items', 'item',
        'orders', 'order', 'payments', 'payment',
        'customers', 'customer', 'clients', 'client',
        'posts', 'post', 'articles', 'article',
        'comments', 'comment', 'messages', 'message',
        'files', 'file', 'uploads', 'upload',
        'images', 'image', 'documents', 'document',
        'categories', 'category', 'tags', 'tag',
        'groups', 'group', 'roles', 'role',
        'permissions', 'permission', 'settings', 'setting',
        'notifications', 'notification', 'events', 'event',
        'reports', 'report', 'analytics', 'analytic',
        'bookings', 'booking', 'reservations', 'reservation',
    ]

    # HTTP methods to test
    HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

    def __init__(self, client: httpx.AsyncClient, base_url: str):
        super().__init__(client, base_url)
        self.discovered_paths: Set[str] = set()
        self.path_patterns: List[PathPattern] = []
        self.max_depth = 3
        self.max_concurrent = 10

    def get_discovery_type(self) -> str:
        return "REST API"

    async def discover(self) -> DiscoveryResult:
        """
        Discover REST API endpoints through pattern recognition
        
        Returns:
            DiscoveryResult with discovered REST endpoints
        """
        endpoints: List[DiscoveredEndpoint] = []
        schemas: List[Dict[str, Any]] = []
        technologies: List[str] = []
        documentation_urls: List[str] = []

        # Phase 1: Discover base API paths
        await self._discover_base_paths()

        # Phase 2: Discover resource endpoints
        await self._discover_resource_endpoints()

        # Phase 3: Discover parameterized endpoints
        await self._discover_parameterized_endpoints()

        # Phase 4: Test HTTP methods on discovered paths
        discovered_endpoints = await self._test_http_methods()
        endpoints.extend(discovered_endpoints)

        # Add REST API to technologies if endpoints found
        if endpoints:
            technologies.append("REST API")

        return DiscoveryResult(
            endpoints=endpoints,
            schemas=schemas,
            technologies=technologies,
            documentation_urls=documentation_urls,
            errors=self.errors
        )

    async def _discover_base_paths(self) -> None:
        """Discover base API paths"""

        # Test common API base paths
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = []

        for path in self.COMMON_API_PATHS:
            task = self._test_path_with_semaphore(semaphore, path)
            tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_path_with_semaphore(self, semaphore: asyncio.Semaphore, path: str) -> None:
        """Test a path with semaphore for concurrency control"""
        async with semaphore:
            response = await self._make_request(path)
            if response and self._is_api_response(response):
                self.discovered_paths.add(path)

    def _is_api_response(self, response: httpx.Response) -> bool:
        """Check if response indicates an API endpoint"""
        # Check status code
        if response.status_code in [200, 201, 400, 401, 403, 404, 405, 500]:
            content_type = response.headers.get('content-type', '').lower()

            # Check for API-like content types
            api_content_types = [
                'application/json',
                'application/xml',
                'application/hal+json',
                'application/vnd.api+json',
                'text/xml'
            ]

            if any(ct in content_type for ct in api_content_types):
                return True

            # Check for API-like headers
            api_headers = [
                'x-api-version',
                'x-ratelimit-limit',
                'x-rate-limit',
                'api-version',
                'x-request-id'
            ]

            if any(header in response.headers for header in api_headers):
                return True

            # Check response content for API indicators
            try:
                if response.headers.get('content-type', '').startswith('application/json'):
                    data = response.json()
                    if isinstance(data, (dict, list)):
                        return True
            except Exception:
                pass

        return False

    async def _discover_resource_endpoints(self) -> None:
        """Discover resource-based endpoints"""

        base_paths = list(self.discovered_paths) if self.discovered_paths else ['']

        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = []

        for base_path in base_paths:
            for resource in self.COMMON_RESOURCES:
                # Test singular and plural forms
                paths_to_test = [
                    f"{base_path}/{resource}".strip('/'),
                    f"{base_path}/{resource}s".strip('/') if not resource.endswith(
                        's') else f"{base_path}/{resource}".strip('/'),
                ]

                for path in paths_to_test:
                    if path not in self.discovered_paths:
                        task = self._test_path_with_semaphore(semaphore, f"/{path}")
                        tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _discover_parameterized_endpoints(self) -> None:
        """Discover parameterized endpoints (e.g., /users/{id})"""

        # Test ID-based endpoints for discovered resources
        resource_paths = [path for path in self.discovered_paths if any(res in path for res in self.COMMON_RESOURCES)]

        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = []

        for resource_path in resource_paths:
            # Test common ID patterns
            id_patterns = ['1', '123', 'test', 'me', 'current']

            for id_pattern in id_patterns:
                parameterized_path = f"{resource_path}/{id_pattern}"
                if parameterized_path not in self.discovered_paths:
                    task = self._test_path_with_semaphore(semaphore, parameterized_path)
                    tasks.append(task)

            # Test nested resources
            for nested_resource in ['comments', 'posts', 'settings', 'profile']:
                nested_path = f"{resource_path}/1/{nested_resource}"
                if nested_path not in self.discovered_paths:
                    task = self._test_path_with_semaphore(semaphore, nested_path)
                    tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_http_methods(self) -> List[DiscoveredEndpoint]:
        """Test different HTTP methods on discovered paths"""
        endpoints: List[DiscoveredEndpoint] = []

        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = []

        for path in self.discovered_paths:
            for method in self.HTTP_METHODS:
                task = self._test_method_on_path(semaphore, path, method)
                tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect valid endpoints
        for result in results:
            if isinstance(result, DiscoveredEndpoint):
                endpoints.append(result)

        return endpoints

    async def _test_method_on_path(
            self,
            semaphore: asyncio.Semaphore,
            path: str,
            method: str
    ) -> Optional[DiscoveredEndpoint]:
        """Test a specific HTTP method on a path"""
        async with semaphore:
            try:
                # Prepare request based on method
                kwargs = {}
                if method in ['POST', 'PUT', 'PATCH']:
                    kwargs['json'] = {}  # Empty JSON body for testing

                response = await self._make_request(path, method=method, **kwargs)

                if response and self._is_valid_method_response(response, method):
                    # Extract parameters from path
                    parameters = self._extract_path_parameters(path, method)

                    # Determine if authentication is required
                    auth_required = response.status_code in [401, 403]

                    # Build full URL
                    full_url = urljoin(self.base_url, path)

                    endpoint = DiscoveredEndpoint(
                        url=full_url,
                        method=method,
                        parameters=parameters,
                        auth_required=auth_required,
                        description=self._generate_endpoint_description(path, method),
                        schema_info={
                            'status_code': response.status_code,
                            'content_type': response.headers.get('content-type', ''),
                            'response_size': len(response.content) if response.content else 0
                        }
                    )

                    return self._normalize_endpoint(endpoint)

            except Exception as e:
                self.errors.append(f"Error testing {method} {path}: {str(e)}")

        return None

    def _is_valid_method_response(self, response: httpx.Response, method: str) -> bool:
        """Check if response indicates the method is valid for this endpoint"""
        status_code = response.status_code

        # Method not allowed
        if status_code == 405:
            return False

        # Valid status codes for different methods
        valid_status_codes = {
            'GET': [200, 201, 400, 401, 403, 404, 500],
            'POST': [200, 201, 400, 401, 403, 422, 500],
            'PUT': [200, 201, 204, 400, 401, 403, 404, 422, 500],
            'PATCH': [200, 204, 400, 401, 403, 404, 422, 500],
            'DELETE': [200, 204, 400, 401, 403, 404, 500],
            'HEAD': [200, 401, 403, 404, 500],
            'OPTIONS': [200, 204, 405]
        }

        return status_code in valid_status_codes.get(method, [200, 400, 401, 403, 404, 500])

    def _extract_path_parameters(self, path: str, method: str) -> Dict[str, Any]:
        """Extract parameters from the path and method"""
        parameters = {
            'path': {},
            'query': {},
            'header': {},
            'body': {}
        }

        # Extract path parameters (look for numeric segments that could be IDs)
        path_segments = path.strip('/').split('/')
        for i, segment in enumerate(path_segments):
            if segment.isdigit() or segment in ['me', 'current', 'test']:
                # Previous segment might be the resource name
                if i > 0:
                    resource_name = path_segments[i - 1]
                    param_name = f"{resource_name}_id" if resource_name else "id"
                    parameters['path'][param_name] = {
                        'type': 'string',
                        'description': f'ID of the {resource_name}',
                        'example': segment
                    }

        # Add common query parameters for GET requests
        if method == 'GET':
            parameters['query'] = {
                'limit': {'type': 'integer', 'description': 'Number of items to return'},
                'offset': {'type': 'integer', 'description': 'Number of items to skip'},
                'page': {'type': 'integer', 'description': 'Page number'},
                'sort': {'type': 'string', 'description': 'Sort field'},
                'order': {'type': 'string', 'description': 'Sort order (asc/desc)'},
                'filter': {'type': 'string', 'description': 'Filter expression'}
            }

        # Add body parameters for write methods
        if method in ['POST', 'PUT', 'PATCH']:
            parameters['body']['application/json'] = {
                'description': f'Request body for {method} operation',
                'required': True
            }

        return parameters

    def _generate_endpoint_description(self, path: str, method: str) -> str:
        """Generate a description for the endpoint based on path and method"""
        path_parts = [part for part in path.strip('/').split('/') if part]

        if not path_parts:
            return f"{method} request to root"

        resource = path_parts[-1] if not path_parts[-1].isdigit() else path_parts[-2] if len(
            path_parts) > 1 else "resource"

        method_descriptions = {
            'GET': f"Retrieve {resource}",
            'POST': f"Create new {resource}",
            'PUT': f"Update {resource}",
            'PATCH': f"Partially update {resource}",
            'DELETE': f"Delete {resource}",
            'HEAD': f"Get {resource} headers",
            'OPTIONS': f"Get {resource} options"
        }

        return method_descriptions.get(method, f"{method} {resource}")

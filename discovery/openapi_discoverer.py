"""
OpenAPI/Swagger Discovery Module

Discovers and parses OpenAPI/Swagger specifications to extract API endpoints,
parameters, and security requirements.
"""

import json
import yaml
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin, urlparse
import httpx

from .base_discoverer import BaseDiscoverer, DiscoveredEndpoint, DiscoveryResult


class OpenAPIDiscoverer(BaseDiscoverer):
    """Discovers APIs through OpenAPI/Swagger specifications"""

    # Common OpenAPI specification paths
    COMMON_OPENAPI_PATHS = [
        '/swagger.json',
        '/swagger.yaml',
        '/swagger.yml',
        '/openapi.json',
        '/openapi.yaml',
        '/openapi.yml',
        '/api-docs',
        '/api/docs',
        '/docs/swagger.json',
        '/docs/openapi.json',
        '/v1/swagger.json',
        '/v2/swagger.json',
        '/v3/swagger.json',
        '/api/v1/swagger.json',
        '/api/v2/swagger.json',
        '/api/v3/swagger.json',
        '/swagger/v1/swagger.json',
        '/swagger/v2/swagger.json',
        '/swagger/v3/swagger.json',
        '/redoc',
        '/swagger-ui.html',
        '/swagger-ui/',
        '/swagger/',
        '/docs/',
        '/documentation/',
        '/api/swagger-ui/',
        '/api/docs/',
    ]

    def __init__(self, client: httpx.AsyncClient, base_url: str):
        super().__init__(client, base_url)
        self.found_specs: List[Dict[str, Any]] = []
        self.swagger_ui_urls: Set[str] = set()

    def get_discovery_type(self) -> str:
        return "OpenAPI/Swagger"

    async def discover(self) -> DiscoveryResult:
        """
        Discover OpenAPI specifications and extract endpoints
        
        Returns:
            DiscoveryResult with discovered endpoints and schemas
        """
        endpoints: List[DiscoveredEndpoint] = []
        schemas: List[Dict[str, Any]] = []
        technologies: List[str] = []
        documentation_urls: List[str] = []

        # First, try to find OpenAPI specifications
        await self._discover_openapi_specs()

        # Parse found specifications
        for spec_data in self.found_specs:
            try:
                parsed_endpoints = await self._parse_openapi_spec(spec_data['content'])
                endpoints.extend(parsed_endpoints)
                schemas.append(spec_data['content'])

                # Extract technology information
                if 'info' in spec_data['content']:
                    info = spec_data['content']['info']
                    if 'x-generator' in info:
                        technologies.append(info['x-generator'])

            except Exception as e:
                self.errors.append(f"Failed to parse OpenAPI spec: {str(e)}")

        # Add Swagger UI URLs as documentation
        documentation_urls.extend(list(self.swagger_ui_urls))

        return DiscoveryResult(
            endpoints=endpoints,
            schemas=schemas,
            technologies=technologies,
            documentation_urls=documentation_urls,
            errors=self.errors
        )

    async def _discover_openapi_specs(self) -> None:
        """Discover OpenAPI specifications by trying common paths"""

        # Try common OpenAPI specification paths
        for path in self.COMMON_OPENAPI_PATHS:
            response = await self._make_request(path)
            if response and response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()

                try:
                    # Try to parse as JSON
                    if 'json' in content_type or path.endswith('.json'):
                        spec_content = response.json()
                        if self._is_valid_openapi_spec(spec_content):
                            self.found_specs.append({
                                'url': response.url,
                                'content': spec_content,
                                'format': 'json'
                            })

                    # Try to parse as YAML
                    elif 'yaml' in content_type or path.endswith(('.yaml', '.yml')):
                        spec_content = yaml.safe_load(response.text)
                        if self._is_valid_openapi_spec(spec_content):
                            self.found_specs.append({
                                'url': response.url,
                                'content': spec_content,
                                'format': 'yaml'
                            })

                    # Check for Swagger UI HTML pages
                    elif 'html' in content_type:
                        if self._is_swagger_ui_page(response.text):
                            self.swagger_ui_urls.add(str(response.url))
                            # Try to extract spec URL from Swagger UI
                            await self._extract_spec_from_swagger_ui(response.text, str(response.url))

                except Exception as e:
                    self.errors.append(f"Failed to parse content from {path}: {str(e)}")

    def _is_valid_openapi_spec(self, content: Dict[str, Any]) -> bool:
        """Check if content is a valid OpenAPI specification"""
        if not isinstance(content, dict):
            return False

        # Check for OpenAPI 3.x
        if 'openapi' in content and isinstance(content['openapi'], str):
            return content['openapi'].startswith('3.')

        # Check for Swagger 2.0
        if 'swagger' in content and content['swagger'] == '2.0':
            return True

        return False

    def _is_swagger_ui_page(self, html_content: str) -> bool:
        """Check if HTML content is a Swagger UI page"""
        swagger_indicators = [
            'swagger-ui',
            'SwaggerUI',
            'swagger.json',
            'openapi.json',
            'redoc',
            'ReDoc'
        ]

        return any(indicator in html_content for indicator in swagger_indicators)

    async def _extract_spec_from_swagger_ui(self, html_content: str, page_url: str) -> None:
        """Extract OpenAPI spec URL from Swagger UI HTML"""
        import re

        # Common patterns for spec URLs in Swagger UI
        patterns = [
            r'url:\s*["\']([^"\']+)["\']',
            r'"url":\s*"([^"]+)"',
            r'spec-url["\']:\s*["\']([^"\']+)["\']',
            r'configUrl:\s*["\']([^"\']+)["\']'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html_content)
            for match in matches:
                if match.endswith(('.json', '.yaml', '.yml')):
                    spec_url = urljoin(page_url, match)
                    response = await self._make_request(match)
                    if response and response.status_code == 200:
                        try:
                            spec_content = response.json()
                            if self._is_valid_openapi_spec(spec_content):
                                self.found_specs.append({
                                    'url': spec_url,
                                    'content': spec_content,
                                    'format': 'json'
                                })
                        except Exception:
                            pass

    async def _parse_openapi_spec(self, spec: Dict[str, Any]) -> List[DiscoveredEndpoint]:
        """Parse OpenAPI specification and extract endpoints"""
        endpoints: List[DiscoveredEndpoint] = []

        if 'paths' not in spec:
            return endpoints

        # Get base path information
        base_path = ""
        if 'basePath' in spec:  # Swagger 2.0
            base_path = spec['basePath']
        elif 'servers' in spec:  # OpenAPI 3.x
            if spec['servers']:
                server_url = spec['servers'][0].get('url', '')
                parsed_url = urlparse(server_url)
                base_path = parsed_url.path

        # Parse each path and method
        for path, path_item in spec['paths'].items():
            if not isinstance(path_item, dict):
                continue

            for method, operation in path_item.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    continue

                if not isinstance(operation, dict):
                    continue

                # Build full URL
                full_path = urljoin(base_path, path.lstrip('/'))
                full_url = urljoin(self.base_url, full_path)

                # Extract parameters
                parameters = self._extract_parameters(operation, path_item)

                # Extract security requirements
                auth_required = self._has_auth_requirement(operation, spec)

                # Get description
                description = operation.get('summary') or operation.get('description')

                endpoint = DiscoveredEndpoint(
                    url=full_url,
                    method=method.upper(),
                    parameters=parameters,
                    auth_required=auth_required,
                    description=description,
                    schema_info={
                        'operation_id': operation.get('operationId'),
                        'tags': operation.get('tags', []),
                        'responses': list(operation.get('responses', {}).keys())
                    }
                )

                endpoints.append(self._normalize_endpoint(endpoint))

        return endpoints

    def _extract_parameters(self, operation: Dict[str, Any], path_item: Dict[str, Any]) -> Dict[str, Any]:
        """Extract parameters from OpenAPI operation"""
        parameters = {
            'query': {},
            'path': {},
            'header': {},
            'body': {}
        }

        # Get parameters from operation and path item
        all_params = []
        all_params.extend(operation.get('parameters', []))
        all_params.extend(path_item.get('parameters', []))

        for param in all_params:
            if not isinstance(param, dict):
                continue

            param_name = param.get('name')
            param_in = param.get('in')
            param_type = param.get('type') or (param.get('schema', {}).get('type') if 'schema' in param else 'string')
            required = param.get('required', False)

            if param_name and param_in in parameters:
                parameters[param_in][param_name] = {
                    'type': param_type,
                    'required': required,
                    'description': param.get('description')
                }

        # Handle request body (OpenAPI 3.x)
        if 'requestBody' in operation:
            request_body = operation['requestBody']
            if 'content' in request_body:
                for content_type, content_info in request_body['content'].items():
                    parameters['body'][content_type] = {
                        'schema': content_info.get('schema'),
                        'required': request_body.get('required', False)
                    }

        return parameters

    def _has_auth_requirement(self, operation: Dict[str, Any], spec: Dict[str, Any]) -> bool:
        """Check if operation requires authentication"""
        # Check operation-level security
        if 'security' in operation:
            return len(operation['security']) > 0

        # Check global security
        if 'security' in spec:
            return len(spec['security']) > 0

        return False

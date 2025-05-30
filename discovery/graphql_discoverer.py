"""
GraphQL Discovery Module

Discovers GraphQL endpoints and performs introspection to extract schema,
queries, mutations, and subscriptions.
"""

import json
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin
import httpx

from .base_discoverer import BaseDiscoverer, DiscoveredEndpoint, DiscoveryResult


class GraphQLDiscoverer(BaseDiscoverer):
    """Discovers GraphQL APIs through endpoint detection and introspection"""

    # Common GraphQL endpoint paths
    COMMON_GRAPHQL_PATHS = [
        '/graphql',
        '/graphql/',
        '/api/graphql',
        '/api/graphql/',
        '/v1/graphql',
        '/v2/graphql',
        '/v3/graphql',
        '/graphql/v1',
        '/graphql/v2',
        '/graphql/v3',
        '/query',
        '/api/query',
        '/gql',
        '/api/gql',
        '/playground',
        '/graphiql',
        '/graphql-playground',
        '/apollo',
        '/api/apollo',
    ]

    # GraphQL introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                ...FullType
            }
            directives {
                name
                description
                locations
                args {
                    ...InputValue
                }
            }
        }
    }
    
    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }
    
    fragment InputValue on __InputValue {
        name
        description
        type { ...TypeRef }
        defaultValue
    }
    
    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    """

    def __init__(self, client: httpx.AsyncClient, base_url: str):
        super().__init__(client, base_url)
        self.graphql_endpoints: Set[str] = set()
        self.schemas: List[Dict[str, Any]] = []

    def get_discovery_type(self) -> str:
        return "GraphQL"

    async def discover(self) -> DiscoveryResult:
        """
        Discover GraphQL endpoints and perform introspection
        
        Returns:
            DiscoveryResult with discovered GraphQL information
        """
        endpoints: List[DiscoveredEndpoint] = []
        schemas: List[Dict[str, Any]] = []
        technologies: List[str] = []
        documentation_urls: List[str] = []

        # First, find GraphQL endpoints
        await self._discover_graphql_endpoints()

        # Perform introspection on found endpoints
        for endpoint_url in self.graphql_endpoints:
            try:
                schema_result = await self._perform_introspection(endpoint_url)
                if schema_result:
                    schemas.append(schema_result)

                    # Extract endpoints from schema
                    extracted_endpoints = self._extract_endpoints_from_schema(
                        endpoint_url, schema_result
                    )
                    endpoints.extend(extracted_endpoints)

                    # Add GraphQL to technologies
                    if "GraphQL" not in technologies:
                        technologies.append("GraphQL")

                    # Check for GraphQL Playground or GraphiQL
                    playground_url = await self._check_for_playground(endpoint_url)
                    if playground_url:
                        documentation_urls.append(playground_url)

            except Exception as e:
                self.errors.append(f"Failed to introspect GraphQL endpoint {endpoint_url}: {str(e)}")

        return DiscoveryResult(
            endpoints=endpoints,
            schemas=schemas,
            technologies=technologies,
            documentation_urls=documentation_urls,
            errors=self.errors
        )

    async def _discover_graphql_endpoints(self) -> None:
        """Discover GraphQL endpoints by trying common paths"""

        for path in self.COMMON_GRAPHQL_PATHS:
            # Try GET request first (for GraphQL Playground/GraphiQL)
            response = await self._make_request(path, method="GET")
            if response and response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()

                # Check if it's HTML (likely GraphQL Playground/GraphiQL)
                if 'html' in content_type and self._is_graphql_playground(response.text):
                    endpoint_url = urljoin(self.base_url, path)
                    self.graphql_endpoints.add(endpoint_url)
                    continue

            # Try POST request with a simple query
            simple_query = {"query": "{ __typename }"}
            response = await self._make_request(
                path,
                method="POST",
                json=simple_query,
                headers={"Content-Type": "application/json"}
            )

            if response and response.status_code == 200:
                try:
                    data = response.json()
                    # Check if response looks like GraphQL
                    if self._is_graphql_response(data):
                        endpoint_url = urljoin(self.base_url, path)
                        self.graphql_endpoints.add(endpoint_url)
                except Exception:
                    pass

    def _is_graphql_playground(self, html_content: str) -> bool:
        """Check if HTML content is a GraphQL Playground or GraphiQL"""
        graphql_indicators = [
            'graphql-playground',
            'GraphQL Playground',
            'graphiql',
            'GraphiQL',
            'Apollo Studio',
            'GraphQL IDE'
        ]

        return any(indicator in html_content for indicator in graphql_indicators)

    def _is_graphql_response(self, response_data: Dict[str, Any]) -> bool:
        """Check if response data looks like a GraphQL response"""
        if not isinstance(response_data, dict):
            return False

        # Check for GraphQL response structure
        return any(key in response_data for key in ['data', 'errors', 'extensions'])

    async def _perform_introspection(self, endpoint_url: str) -> Optional[Dict[str, Any]]:
        """Perform GraphQL introspection on an endpoint"""

        introspection_request = {
            "query": self.INTROSPECTION_QUERY
        }

        response = await self._make_request(
            endpoint_url.replace(self.base_url, ''),
            method="POST",
            json=introspection_request,
            headers={"Content-Type": "application/json"}
        )

        if not response or response.status_code != 200:
            return None

        try:
            data = response.json()
            if 'data' in data and '__schema' in data['data']:
                return data['data']['__schema']
            elif 'errors' in data:
                # Introspection might be disabled
                self.errors.append(f"Introspection disabled on {endpoint_url}")
                return None
        except Exception as e:
            self.errors.append(f"Failed to parse introspection response from {endpoint_url}: {str(e)}")

        return None

    def _extract_endpoints_from_schema(
            self,
            endpoint_url: str,
            schema: Dict[str, Any]
    ) -> List[DiscoveredEndpoint]:
        """Extract GraphQL operations from introspection schema"""
        endpoints: List[DiscoveredEndpoint] = []

        # Get root types
        query_type = schema.get('queryType', {}).get('name')
        mutation_type = schema.get('mutationType', {}).get('name')
        subscription_type = schema.get('subscriptionType', {}).get('name')

        # Find types and their fields
        types = {t['name']: t for t in schema.get('types', []) if t.get('name')}

        # Extract queries
        if query_type and query_type in types:
            query_fields = types[query_type].get('fields', [])
            for field in query_fields:
                endpoint = self._create_graphql_endpoint(
                    endpoint_url, 'QUERY', field, 'query'
                )
                endpoints.append(endpoint)

        # Extract mutations
        if mutation_type and mutation_type in types:
            mutation_fields = types[mutation_type].get('fields', [])
            for field in mutation_fields:
                endpoint = self._create_graphql_endpoint(
                    endpoint_url, 'POST', field, 'mutation'
                )
                endpoints.append(endpoint)

        # Extract subscriptions
        if subscription_type and subscription_type in types:
            subscription_fields = types[subscription_type].get('fields', [])
            for field in subscription_fields:
                endpoint = self._create_graphql_endpoint(
                    endpoint_url, 'WEBSOCKET', field, 'subscription'
                )
                endpoints.append(endpoint)

        return endpoints

    def _create_graphql_endpoint(
            self,
            endpoint_url: str,
            method: str,
            field: Dict[str, Any],
            operation_type: str
    ) -> DiscoveredEndpoint:
        """Create a DiscoveredEndpoint from a GraphQL field"""

        # Extract arguments
        args = {}
        for arg in field.get('args', []):
            arg_name = arg.get('name')
            arg_type = self._parse_graphql_type(arg.get('type', {}))
            args[arg_name] = {
                'type': arg_type,
                'description': arg.get('description')
            }

        # Create parameters structure
        parameters = {
            'query': {},
            'variables': args,
            'operation_name': field.get('name')
        }

        return DiscoveredEndpoint(
            url=endpoint_url,
            method=method,
            parameters=parameters,
            description=field.get('description'),
            schema_info={
                'operation_type': operation_type,
                'field_name': field.get('name'),
                'return_type': self._parse_graphql_type(field.get('type', {})),
                'deprecated': field.get('isDeprecated', False),
                'deprecation_reason': field.get('deprecationReason')
            }
        )

    def _parse_graphql_type(self, type_info: Dict[str, Any]) -> str:
        """Parse GraphQL type information into a string representation"""
        if not type_info:
            return "Unknown"

        kind = type_info.get('kind')
        name = type_info.get('name')

        if kind == 'NON_NULL':
            inner_type = self._parse_graphql_type(type_info.get('ofType', {}))
            return f"{inner_type}!"
        elif kind == 'LIST':
            inner_type = self._parse_graphql_type(type_info.get('ofType', {}))
            return f"[{inner_type}]"
        elif name:
            return name
        else:
            return "Unknown"

    async def _check_for_playground(self, endpoint_url: str) -> Optional[str]:
        """Check if GraphQL Playground or GraphiQL is available"""

        # Common playground paths relative to GraphQL endpoint
        playground_paths = [
            '',  # Same path as GraphQL endpoint
            '/playground',
            '/graphiql',
            '../playground',
            '../graphiql'
        ]

        for path in playground_paths:
            if path:
                playground_url = urljoin(endpoint_url, path)
            else:
                playground_url = endpoint_url

            response = await self._make_request(
                playground_url.replace(self.base_url, ''),
                method="GET"
            )

            if response and response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                if 'html' in content_type and self._is_graphql_playground(response.text):
                    return playground_url

        return None

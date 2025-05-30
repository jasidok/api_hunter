"""
Documentation Scraper Module

Discovers and analyzes API documentation including:
- API documentation pages
- Interactive documentation (Swagger UI, GraphiQL, etc.)
- README files and wiki pages
- Code examples and tutorials
"""

import re
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass
import httpx

from .base_discoverer import BaseDiscoverer, DiscoveredEndpoint, DiscoveryResult


@dataclass
class DocumentationPage:
    """Represents a discovered documentation page"""
    url: str
    title: str
    doc_type: str
    content_summary: str
    endpoints_mentioned: List[str]
    importance_score: float


class DocumentationScraper(BaseDiscoverer):
    """Scrapes and analyzes API documentation"""

    # Common documentation paths
    DOCUMENTATION_PATHS = [
        '/docs',
        '/docs/',
        '/documentation',
        '/documentation/',
        '/api-docs',
        '/api-docs/',
        '/api/docs',
        '/api/docs/',
        '/swagger',
        '/swagger/',
        '/swagger-ui',
        '/swagger-ui/',
        '/redoc',
        '/redoc/',
        '/graphiql',
        '/graphiql/',
        '/playground',
        '/playground/',
        '/reference',
        '/reference/',
        '/guide',
        '/guide/',
        '/tutorial',
        '/tutorial/',
        '/help',
        '/help/',
        '/readme',
        '/readme.md',
        '/README.md',
        '/wiki',
        '/wiki/',
        '/manual',
        '/manual/',
        '/api-reference',
        '/api-guide',
        '/developer',
        '/developer/',
        '/dev',
        '/dev/',
        '/portal',
        '/portal/',
    ]

    # Documentation file extensions
    DOC_EXTENSIONS = ['.md', '.txt', '.html', '.htm', '.pdf', '.doc', '.docx']

    # Documentation indicators in content
    DOC_INDICATORS = [
        'api documentation',
        'api reference',
        'rest api',
        'graphql',
        'endpoint',
        'authentication',
        'authorization',
        'getting started',
        'quick start',
        'tutorial',
        'examples',
        'curl',
        'http request',
        'json response',
        'swagger',
        'openapi',
        'postman',
    ]

    def __init__(self, client: httpx.AsyncClient, base_url: str):
        super().__init__(client, base_url)
        self.documentation_pages: List[DocumentationPage] = []
        self.discovered_links: Set[str] = set()

    def get_discovery_type(self) -> str:
        return "Documentation Scraping"

    async def discover(self) -> DiscoveryResult:
        """
        Discover and analyze API documentation
        
        Returns:
            DiscoveryResult with discovered documentation and extracted endpoints
        """
        endpoints: List[DiscoveredEndpoint] = []
        schemas: List[Dict[str, Any]] = []
        technologies: List[str] = []
        documentation_urls: List[str] = []

        # Phase 1: Discover documentation pages
        await self._discover_documentation_pages()

        # Phase 2: Scrape and analyze content
        await self._scrape_documentation_content()

        # Phase 3: Extract endpoints from documentation
        extracted_endpoints = await self._extract_endpoints_from_docs()
        endpoints.extend(extracted_endpoints)

        # Convert documentation pages to URLs
        documentation_urls = [page.url for page in self.documentation_pages]

        # Add documentation-related technologies
        if self.documentation_pages:
            doc_types = set(page.doc_type for page in self.documentation_pages)
            technologies.extend(list(doc_types))

        return DiscoveryResult(
            endpoints=endpoints,
            schemas=schemas,
            technologies=technologies,
            documentation_urls=documentation_urls,
            errors=self.errors
        )

    async def _discover_documentation_pages(self) -> None:
        """Discover documentation pages by trying common paths"""

        for path in self.DOCUMENTATION_PATHS:
            try:
                response = await self._make_request(path)
                if response and response.status_code == 200:
                    if self._is_documentation_page(response):
                        doc_type = self._identify_documentation_type(response)
                        title = self._extract_page_title(response.text)

                        doc_page = DocumentationPage(
                            url=str(response.url),
                            title=title,
                            doc_type=doc_type,
                            content_summary="",
                            endpoints_mentioned=[],
                            importance_score=0.0
                        )

                        self.documentation_pages.append(doc_page)

                        # Extract links for further exploration
                        await self._extract_documentation_links(response)

            except Exception as e:
                self.errors.append(f"Error checking documentation path {path}: {str(e)}")

    def _is_documentation_page(self, response: httpx.Response) -> bool:
        """Check if response is a documentation page"""
        content_type = response.headers.get('content-type', '').lower()

        # Check content type
        if any(ct in content_type for ct in ['text/html', 'text/markdown', 'text/plain']):
            content = response.text.lower()

            # Check for documentation indicators
            indicator_count = sum(1 for indicator in self.DOC_INDICATORS if indicator in content)

            # If multiple indicators found, likely documentation
            if indicator_count >= 2:
                return True

            # Check title for documentation keywords
            title = self._extract_page_title(response.text).lower()
            if any(keyword in title for keyword in ['documentation', 'docs', 'api', 'reference', 'guide']):
                return True

        return False

    def _identify_documentation_type(self, response: httpx.Response) -> str:
        """Identify the type of documentation"""
        content = response.text.lower()
        url = str(response.url).lower()

        # Check for specific documentation types
        if 'swagger' in content or 'swagger' in url:
            return 'Swagger UI'
        elif 'redoc' in content or 'redoc' in url:
            return 'ReDoc'
        elif 'graphiql' in content or 'graphiql' in url:
            return 'GraphiQL'
        elif 'playground' in content or 'playground' in url:
            return 'GraphQL Playground'
        elif 'postman' in content:
            return 'Postman Documentation'
        elif 'readme' in url or '# ' in content:
            return 'README/Markdown'
        elif 'wiki' in url:
            return 'Wiki'
        elif 'tutorial' in content or 'getting started' in content:
            return 'Tutorial'
        elif 'reference' in content or 'api reference' in content:
            return 'API Reference'
        else:
            return 'General Documentation'

    def _extract_page_title(self, html_content: str) -> str:
        """Extract title from HTML page"""
        # Try HTML title tag first
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()

        # Try h1 tag
        h1_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html_content, re.IGNORECASE)
        if h1_match:
            return h1_match.group(1).strip()

        # Try markdown title
        md_title_match = re.search(r'^#\s+(.+)$', html_content, re.MULTILINE)
        if md_title_match:
            return md_title_match.group(1).strip()

        return "Unknown Title"

    async def _extract_documentation_links(self, response: httpx.Response) -> None:
        """Extract links from documentation page for further exploration"""
        content = response.text
        base_url = str(response.url)

        # Extract HTML links
        html_links = re.findall(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE)

        # Extract markdown links
        md_links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content)

        all_links = html_links + [link[1] for link in md_links]

        for link in all_links:
            # Skip external links, anchors, and non-documentation links
            if (link.startswith('http') and not link.startswith(self.base_url) or
                    link.startswith('#') or
                    link.startswith('mailto:') or
                    link.startswith('javascript:')):
                continue

            # Convert relative links to absolute
            absolute_link = urljoin(base_url, link)

            # Check if link looks like documentation
            if self._looks_like_documentation_link(absolute_link):
                self.discovered_links.add(absolute_link)

    def _looks_like_documentation_link(self, url: str) -> bool:
        """Check if URL looks like a documentation link"""
        url_lower = url.lower()

        # Check for documentation keywords in URL
        doc_keywords = [
            'doc', 'guide', 'tutorial', 'reference', 'api',
            'help', 'manual', 'readme', 'wiki', 'example'
        ]

        if any(keyword in url_lower for keyword in doc_keywords):
            return True

        # Check for documentation file extensions
        for ext in self.DOC_EXTENSIONS:
            if url_lower.endswith(ext):
                return True

        return False

    async def _scrape_documentation_content(self) -> None:
        """Scrape content from discovered documentation pages"""

        # Scrape discovered links
        for link in list(self.discovered_links):
            try:
                response = await self._make_request(link.replace(self.base_url, ''))
                if response and response.status_code == 200:
                    if self._is_documentation_page(response):
                        doc_type = self._identify_documentation_type(response)
                        title = self._extract_page_title(response.text)

                        doc_page = DocumentationPage(
                            url=str(response.url),
                            title=title,
                            doc_type=doc_type,
                            content_summary="",
                            endpoints_mentioned=[],
                            importance_score=0.0
                        )

                        self.documentation_pages.append(doc_page)

            except Exception as e:
                self.errors.append(f"Error scraping documentation link {link}: {str(e)}")

        # Analyze content of all discovered pages
        for doc_page in self.documentation_pages:
            try:
                response = await self._make_request(doc_page.url.replace(self.base_url, ''))
                if response and response.status_code == 200:
                    await self._analyze_documentation_content(doc_page, response.text)

            except Exception as e:
                self.errors.append(f"Error analyzing documentation content for {doc_page.url}: {str(e)}")

    async def _analyze_documentation_content(self, doc_page: DocumentationPage, content: str) -> None:
        """Analyze documentation content for endpoints and importance"""

        # Extract mentioned endpoints
        endpoints = self._extract_endpoint_mentions(content)
        doc_page.endpoints_mentioned = endpoints

        # Generate content summary
        doc_page.content_summary = self._generate_content_summary(content)

        # Calculate importance score
        doc_page.importance_score = self._calculate_importance_score(doc_page, content)

    def _extract_endpoint_mentions(self, content: str) -> List[str]:
        """Extract endpoint mentions from documentation content"""
        endpoints = []

        # Pattern for API endpoints
        endpoint_patterns = [
            r'(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([/\w\-\{\}]+)',
            r'([/\w\-\{\}]+)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)',
            r'`([/\w\-\{\}]+)`',
            r'"([/\w\-\{\}]+)"',
            r'https?://[^/\s]+(/[^\s\)]*)',
            r'curl.*?(https?://[^\s]+)',
        ]

        for pattern in endpoint_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    # Extract the URL part from tuple matches
                    for part in match:
                        if part.startswith('/') or part.startswith('http'):
                            endpoints.append(part)
                            break
                else:
                    endpoints.append(match)

        # Clean and deduplicate endpoints
        cleaned_endpoints = []
        for endpoint in endpoints:
            # Remove query parameters and fragments
            endpoint = endpoint.split('?')[0].split('#')[0]

            # Only include if it looks like a valid endpoint
            if (endpoint.startswith('/') and len(endpoint) > 1 and
                    not endpoint.endswith('.css') and not endpoint.endswith('.js') and
                    not endpoint.endswith('.png') and not endpoint.endswith('.jpg')):
                cleaned_endpoints.append(endpoint)

        return list(set(cleaned_endpoints))

    def _generate_content_summary(self, content: str) -> str:
        """Generate a summary of the documentation content"""
        # Remove HTML tags
        clean_content = re.sub(r'<[^>]+>', '', content)

        # Get first few sentences
        sentences = re.split(r'[.!?]+', clean_content)
        summary_sentences = []
        char_count = 0

        for sentence in sentences[:5]:  # Max 5 sentences
            sentence = sentence.strip()
            if sentence and char_count + len(sentence) < 500:
                summary_sentences.append(sentence)
                char_count += len(sentence)
            else:
                break

        return '. '.join(summary_sentences)

    def _calculate_importance_score(self, doc_page: DocumentationPage, content: str) -> float:
        """Calculate importance score for documentation page"""
        score = 0.0

        # Score based on documentation type
        type_scores = {
            'Swagger UI': 0.9,
            'ReDoc': 0.9,
            'GraphiQL': 0.8,
            'GraphQL Playground': 0.8,
            'API Reference': 0.8,
            'Tutorial': 0.7,
            'README/Markdown': 0.6,
            'General Documentation': 0.5,
            'Wiki': 0.4,
        }
        score += type_scores.get(doc_page.doc_type, 0.3)

        # Score based on endpoint mentions
        score += min(len(doc_page.endpoints_mentioned) * 0.1, 0.5)

        # Score based on content quality indicators
        content_lower = content.lower()
        quality_indicators = [
            'example', 'curl', 'request', 'response', 'json',
            'authentication', 'authorization', 'parameter',
            'header', 'status code', 'error', 'rate limit'
        ]

        indicator_count = sum(1 for indicator in quality_indicators if indicator in content_lower)
        score += min(indicator_count * 0.05, 0.3)

        # Score based on content length (more comprehensive docs)
        if len(content) > 10000:
            score += 0.2
        elif len(content) > 5000:
            score += 0.1

        return min(score, 1.0)  # Cap at 1.0

    async def _extract_endpoints_from_docs(self) -> List[DiscoveredEndpoint]:
        """Extract discoverable endpoints from documentation"""
        endpoints = []

        for doc_page in self.documentation_pages:
            for endpoint_path in doc_page.endpoints_mentioned:
                try:
                    # Try to determine HTTP method (default to GET)
                    method = self._guess_http_method(endpoint_path, doc_page)

                    # Build full URL
                    if endpoint_path.startswith('/'):
                        full_url = urljoin(self.base_url, endpoint_path)
                    else:
                        full_url = endpoint_path

                    # Create endpoint
                    endpoint = DiscoveredEndpoint(
                        url=full_url,
                        method=method,
                        description=f"Endpoint mentioned in {doc_page.doc_type}: {doc_page.title}",
                        schema_info={
                            'source': 'documentation',
                            'doc_page': doc_page.url,
                            'doc_type': doc_page.doc_type,
                            'importance_score': doc_page.importance_score
                        }
                    )

                    endpoints.append(self._normalize_endpoint(endpoint))

                except Exception as e:
                    self.errors.append(f"Error processing endpoint {endpoint_path}: {str(e)}")

        return endpoints

    def _guess_http_method(self, endpoint_path: str, doc_page: DocumentationPage) -> str:
        """Guess HTTP method based on endpoint path and context"""
        path_lower = endpoint_path.lower()

        # Check for REST conventions
        if any(word in path_lower for word in ['create', 'post', 'add', 'new']):
            return 'POST'
        elif any(word in path_lower for word in ['update', 'put', 'edit', 'modify']):
            return 'PUT'
        elif any(word in path_lower for word in ['patch', 'partial']):
            return 'PATCH'
        elif any(word in path_lower for word in ['delete', 'remove', 'destroy']):
            return 'DELETE'
        else:
            return 'GET'  # Default to GET

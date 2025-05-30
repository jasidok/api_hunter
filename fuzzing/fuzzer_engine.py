"""
Core fuzzing engine for intelligent API security testing.

This module provides the main fuzzing capabilities including coordinated
fuzzing campaigns, payload generation, response analysis, and intelligent
mutation strategies.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import time
import random

from ..core.config import Config
from ..core.http_client import HTTPClient
from .payload_generator import PayloadGenerator
from .parameter_discoverer import ParameterDiscoverer
from .response_analyzer import ResponseAnalyzer
from .wordlist_manager import WordlistManager
from .mutation_engine import MutationEngine
from .binary_payload_generator import BinaryPayloadGenerator, EnhancedPayloadGenerator

logger = logging.getLogger(__name__)


class FuzzingStrategy(Enum):
    """Different fuzzing strategies."""
    BREADTH_FIRST = "breadth_first"
    DEPTH_FIRST = "depth_first"
    RANDOM = "random"
    INTELLIGENT = "intelligent"
    HYBRID = "hybrid"


@dataclass
class FuzzingResult:
    """Result from a fuzzing operation."""
    request: Dict[str, Any]
    response: Dict[str, Any]
    payload: str
    parameter: str
    vulnerability_indicators: List[str]
    confidence: float
    response_time: float
    status_code: int
    content_length: int
    unique_response: bool


@dataclass
class FuzzingSession:
    """Fuzzing session configuration and state."""
    target_url: str
    strategy: FuzzingStrategy
    max_requests: int
    request_delay: float
    timeout: int
    follow_redirects: bool
    custom_headers: Dict[str, str]
    authentication: Optional[Dict[str, Any]]
    start_time: float
    total_requests: int = 0
    vulnerabilities_found: int = 0
    unique_responses: int = 0


class FuzzerEngine:
    """Advanced fuzzing engine with AI-powered optimization."""

    def __init__(self, config: Config, http_client: HTTPClient):
        self.config = config
        self.http_client = http_client
        self.payload_generator = PayloadGenerator(config)
        self.binary_payload_generator = EnhancedPayloadGenerator(config)
        self.parameter_discoverer = ParameterDiscoverer(http_client)
        self.response_analyzer = ResponseAnalyzer()
        self.wordlist_manager = WordlistManager(config)
        self.mutation_engine = MutationEngine()

        # Fuzzing state
        self.active_sessions: Dict[str, FuzzingSession] = {}
        self.response_cache: Dict[str, Dict] = {}
        self.vulnerability_patterns: Dict[str, List[str]] = self._load_vulnerability_patterns()

    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load vulnerability detection patterns."""
        return {
            "error_disclosure": [
                "stack trace", "traceback", "error occurred",
                "exception", "internal server error", "debug"
            ],
            "injection": [
                "sql syntax", "mysql_fetch", "ora-", "sqlite_",
                "postgresql", "syntax error near"
            ],
            "file_inclusion": [
                "failed to open stream", "no such file",
                "permission denied", "include_path"
            ],
            "xss": [
                "<script", "javascript:", "onerror=", "onload="
            ],
            "ssrf": [
                "connection refused", "timeout", "dns resolution",
                "could not resolve host"
            ]
        }

    async def start_fuzzing_session(
            self,
            target_url: str,
            strategy: FuzzingStrategy = FuzzingStrategy.INTELLIGENT,
            max_requests: int = 1000,
            request_delay: float = 0.1,
            timeout: int = 30,
            follow_redirects: bool = True,
            custom_headers: Dict[str, str] = None,
            authentication: Dict[str, Any] = None
    ) -> str:
        """
        Start a new fuzzing session.
        
        Args:
            target_url: Target API endpoint
            strategy: Fuzzing strategy to use
            max_requests: Maximum number of requests
            request_delay: Delay between requests
            timeout: Request timeout
            follow_redirects: Whether to follow redirects
            custom_headers: Custom headers to include
            authentication: Authentication configuration
            
        Returns:
            Session ID
        """
        session_id = f"fuzz_{int(time.time())}_{random.randint(1000, 9999)}"

        session = FuzzingSession(
            target_url=target_url,
            strategy=strategy,
            max_requests=max_requests,
            request_delay=request_delay,
            timeout=timeout,
            follow_redirects=follow_redirects,
            custom_headers=custom_headers or {},
            authentication=authentication,
            start_time=time.time()
        )

        self.active_sessions[session_id] = session

        # Start fuzzing in background
        asyncio.create_task(self._run_fuzzing_session(session_id))

        logger.info(f"Started fuzzing session {session_id} for {target_url}")
        return session_id

    async def _run_fuzzing_session(self, session_id: str):
        """Run the fuzzing session."""
        session = self.active_sessions.get(session_id)
        if not session:
            return

        try:
            # Discover parameters first
            parameters = await self.parameter_discoverer.discover_parameters(
                session.target_url,
                session.custom_headers,
                session.authentication
            )

            if session.strategy == FuzzingStrategy.INTELLIGENT:
                await self._intelligent_fuzzing(session_id, parameters)
            elif session.strategy == FuzzingStrategy.BREADTH_FIRST:
                await self._breadth_first_fuzzing(session_id, parameters)
            elif session.strategy == FuzzingStrategy.DEPTH_FIRST:
                await self._depth_first_fuzzing(session_id, parameters)
            elif session.strategy == FuzzingStrategy.RANDOM:
                await self._random_fuzzing(session_id, parameters)
            elif session.strategy == FuzzingStrategy.HYBRID:
                await self._hybrid_fuzzing(session_id, parameters)

        except Exception as e:
            logger.error(f"Fuzzing session {session_id} failed: {e}")
        finally:
            logger.info(f"Fuzzing session {session_id} completed")

    async def _intelligent_fuzzing(self, session_id: str, parameters: List[str]):
        """AI-powered intelligent fuzzing strategy."""
        session = self.active_sessions[session_id]

        # Start with baseline requests
        baseline_responses = await self._get_baseline_responses(session)

        # Analyze endpoint context
        context = await self._analyze_endpoint_context(session.target_url, baseline_responses)

        # Generate context-aware payloads
        payloads = await self.payload_generator.generate_context_payloads(
            context, parameters
        )

        # Prioritize payloads based on context
        prioritized_payloads = self._prioritize_payloads(payloads, context)

        # Execute fuzzing with intelligent adaptation
        for param in parameters:
            if session.total_requests >= session.max_requests:
                break

            for payload in prioritized_payloads:
                if session.total_requests >= session.max_requests:
                    break

                result = await self._execute_fuzz_request(session, param, payload)
                await self._analyze_and_adapt(session_id, result)

                await asyncio.sleep(session.request_delay)

    async def _breadth_first_fuzzing(self, session_id: str, parameters: List[str]):
        """Breadth-first fuzzing strategy."""
        session = self.active_sessions[session_id]

        # Get all payloads for all parameters first
        all_payloads = await self.payload_generator.generate_all_payloads()

        # Test each payload against all parameters before moving to next payload
        for payload in all_payloads:
            if session.total_requests >= session.max_requests:
                break

            for param in parameters:
                if session.total_requests >= session.max_requests:
                    break

                result = await self._execute_fuzz_request(session, param, payload)
                await self._analyze_result(result)

                await asyncio.sleep(session.request_delay)

    async def _depth_first_fuzzing(self, session_id: str, parameters: List[str]):
        """Depth-first fuzzing strategy."""
        session = self.active_sessions[session_id]

        # Test all payloads for each parameter before moving to next parameter
        for param in parameters:
            if session.total_requests >= session.max_requests:
                break

            payloads = await self.payload_generator.generate_parameter_payloads(param)

            for payload in payloads:
                if session.total_requests >= session.max_requests:
                    break

                result = await self._execute_fuzz_request(session, param, payload)
                await self._analyze_result(result)

                await asyncio.sleep(session.request_delay)

    async def _random_fuzzing(self, session_id: str, parameters: List[str]):
        """Random fuzzing strategy."""
        session = self.active_sessions[session_id]

        all_payloads = await self.payload_generator.generate_all_payloads()

        while session.total_requests < session.max_requests:
            param = random.choice(parameters)
            payload = random.choice(all_payloads)

            result = await self._execute_fuzz_request(session, param, payload)
            await self._analyze_result(result)

            await asyncio.sleep(session.request_delay)

    async def _hybrid_fuzzing(self, session_id: str, parameters: List[str]):
        """Hybrid fuzzing combining multiple strategies."""
        session = self.active_sessions[session_id]

        # Split requests between strategies
        intelligent_requests = session.max_requests // 2
        random_requests = session.max_requests - intelligent_requests

        # Run intelligent fuzzing first
        original_max = session.max_requests
        session.max_requests = intelligent_requests
        await self._intelligent_fuzzing(session_id, parameters)

        # Then run random fuzzing
        session.max_requests = original_max
        await self._random_fuzzing(session_id, parameters)

    async def _execute_fuzz_request(
            self,
            session: FuzzingSession,
            parameter: str,
            payload: str
    ) -> FuzzingResult:
        """Execute a single fuzz request."""
        # Prepare request
        request_data = await self._prepare_fuzz_request(session, parameter, payload)

        # Send request
        start_time = time.time()
        try:
            response = await self.http_client.request(
                method=request_data.get('method', 'GET'),
                url=request_data['url'],
                headers=request_data.get('headers', {}),
                params=request_data.get('params', {}),
                json=request_data.get('json'),
                data=request_data.get('data'),
                timeout=session.timeout,
                follow_redirects=session.follow_redirects
            )
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            response = {
                'status_code': 0,
                'headers': {},
                'body': str(e),
                'response_time': time.time() - start_time
            }

        response_time = time.time() - start_time
        session.total_requests += 1

        # Analyze response
        vulnerability_indicators = self._detect_vulnerability_indicators(response)
        confidence = self._calculate_vulnerability_confidence(vulnerability_indicators)
        unique_response = self._is_unique_response(response)

        if unique_response:
            session.unique_responses += 1

        if vulnerability_indicators:
            session.vulnerabilities_found += 1

        return FuzzingResult(
            request=request_data,
            response=response,
            payload=payload,
            parameter=parameter,
            vulnerability_indicators=vulnerability_indicators,
            confidence=confidence,
            response_time=response_time,
            status_code=response.get('status_code', 0),
            content_length=len(str(response.get('body', ''))),
            unique_response=unique_response
        )

    async def _prepare_fuzz_request(
            self,
            session: FuzzingSession,
            parameter: str,
            payload: str
    ) -> Dict[str, Any]:
        """Prepare a fuzz request with the given payload."""
        request_data = {
            'url': session.target_url,
            'method': 'GET',
            'headers': session.custom_headers.copy()
        }

        # Add authentication if provided
        if session.authentication:
            request_data['headers'].update(
                await self._prepare_authentication(session.authentication)
            )

        # Inject payload into parameter
        if 'query' in parameter or 'param' in parameter:
            request_data['params'] = {parameter: payload}
        elif 'header' in parameter:
            request_data['headers'][parameter] = payload
        elif 'body' in parameter or 'json' in parameter:
            request_data['json'] = {parameter: payload}
        elif 'form' in parameter:
            request_data['data'] = {parameter: payload}
        else:
            # Default to query parameter
            request_data['params'] = {parameter: payload}

        return request_data

    async def _prepare_authentication(self, auth_config: Dict[str, Any]) -> Dict[str, str]:
        """Prepare authentication headers."""
        headers = {}

        if auth_config.get('type') == 'bearer':
            headers['Authorization'] = f"Bearer {auth_config['token']}"
        elif auth_config.get('type') == 'api_key':
            headers[auth_config['header']] = auth_config['key']
        elif auth_config.get('type') == 'basic':
            import base64
            credentials = f"{auth_config['username']}:{auth_config['password']}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers['Authorization'] = f"Basic {encoded}"

        return headers

    def _detect_vulnerability_indicators(self, response: Dict[str, Any]) -> List[str]:
        """Detect vulnerability indicators in response."""
        indicators = []
        response_text = str(response.get('body', '')).lower()
        status_code = response.get('status_code', 200)

        # Check each vulnerability pattern
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                if pattern.lower() in response_text:
                    indicators.append(f"{vuln_type}:{pattern}")

        # Check for interesting status codes
        if status_code in [500, 503, 504]:
            indicators.append(f"error_status:{status_code}")
        elif status_code in [403, 401]:
            indicators.append(f"auth_status:{status_code}")

        return indicators

    def _calculate_vulnerability_confidence(self, indicators: List[str]) -> float:
        """Calculate confidence score for vulnerability indicators."""
        if not indicators:
            return 0.0

        # Weight different indicator types
        weights = {
            'error_disclosure': 0.8,
            'injection': 0.9,
            'file_inclusion': 0.7,
            'xss': 0.6,
            'ssrf': 0.8,
            'error_status': 0.3,
            'auth_status': 0.4
        }

        total_weight = 0.0
        for indicator in indicators:
            vuln_type = indicator.split(':')[0]
            total_weight += weights.get(vuln_type, 0.5)

        # Normalize to 0-1 range
        return min(total_weight / len(indicators), 1.0)

    def _is_unique_response(self, response: Dict[str, Any]) -> bool:
        """Check if response is unique (not seen before)."""
        # Create response signature
        signature = self._create_response_signature(response)

        if signature not in self.response_cache:
            self.response_cache[signature] = response
            return True

        return False

    def _create_response_signature(self, response: Dict[str, Any]) -> str:
        """Create a signature for response deduplication."""
        import hashlib

        # Use status code, content length, and hash of body
        status = str(response.get('status_code', 0))
        body = str(response.get('body', ''))
        content_hash = hashlib.md5(body.encode()).hexdigest()[:8]
        length = str(len(body))

        return f"{status}:{length}:{content_hash}"

    async def _get_baseline_responses(self, session: FuzzingSession) -> Dict[str, Any]:
        """Get baseline responses for comparison."""
        baseline = {}

        try:
            # Normal request
            response = await self.http_client.request(
                method='GET',
                url=session.target_url,
                headers=session.custom_headers,
                timeout=session.timeout
            )
            baseline['normal'] = response

            # Request with invalid parameter
            response = await self.http_client.request(
                method='GET',
                url=session.target_url,
                headers=session.custom_headers,
                params={'invalid_param': 'test'},
                timeout=session.timeout
            )
            baseline['invalid_param'] = response

        except Exception as e:
            logger.debug(f"Failed to get baseline: {e}")

        return baseline

    async def _analyze_endpoint_context(
            self,
            url: str,
            baseline_responses: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze endpoint context for intelligent fuzzing."""
        context = {
            'technology': 'unknown',
            'framework': 'unknown',
            'database': 'unknown',
            'authentication_required': False,
            'content_type': 'unknown',
            'response_patterns': []
        }

        # Analyze normal response
        normal_response = baseline_responses.get('normal', {})
        headers = normal_response.get('headers', {})
        body = str(normal_response.get('body', ''))

        # Detect technology stack
        server_header = headers.get('server', '').lower()
        if 'apache' in server_header:
            context['technology'] = 'apache'
        elif 'nginx' in server_header:
            context['technology'] = 'nginx'
        elif 'iis' in server_header:
            context['technology'] = 'iis'

        # Detect framework
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            context['framework'] = 'php'
        elif 'asp.net' in powered_by:
            context['framework'] = 'aspnet'
        elif 'express' in powered_by:
            context['framework'] = 'express'

        # Check for database indicators in responses
        if any(db in body.lower() for db in ['mysql', 'postgresql', 'sqlite', 'mssql']):
            for db in ['mysql', 'postgresql', 'sqlite', 'mssql']:
                if db in body.lower():
                    context['database'] = db
                    break

        # Check authentication requirements
        if normal_response.get('status_code') in [401, 403]:
            context['authentication_required'] = True

        # Detect content type
        content_type = headers.get('content-type', '').lower()
        if 'json' in content_type:
            context['content_type'] = 'json'
        elif 'xml' in content_type:
            context['content_type'] = 'xml'
        elif 'html' in content_type:
            context['content_type'] = 'html'

        return context

    def _prioritize_payloads(
            self,
            payloads: List[str],
            context: Dict[str, Any]
    ) -> List[str]:
        """Prioritize payloads based on context."""
        prioritized = []

        # High priority payloads based on context
        if context['database'] == 'mysql':
            mysql_payloads = [p for p in payloads if 'mysql' in p.lower() or 'sleep(' in p.lower()]
            prioritized.extend(mysql_payloads)

        if context['framework'] == 'php':
            php_payloads = [p for p in payloads if 'php' in p.lower() or '../' in p]
            prioritized.extend(php_payloads)

        if context['content_type'] == 'json':
            json_payloads = [p for p in payloads if '{' in p or '"' in p]
            prioritized.extend(json_payloads)

        # Add remaining payloads
        remaining = [p for p in payloads if p not in prioritized]
        prioritized.extend(remaining)

        return prioritized

    async def _analyze_and_adapt(self, session_id: str, result: FuzzingResult):
        """Analyze result and adapt fuzzing strategy."""
        if result.vulnerability_indicators:
            logger.info(f"Potential vulnerability found in session {session_id}: {result.vulnerability_indicators}")

            # Generate related payloads for further testing
            related_payloads = await self.mutation_engine.generate_mutations(
                result.payload,
                result.vulnerability_indicators
            )

            # Queue related payloads for testing
            # (This would be implemented with a priority queue in a full implementation)

    async def _analyze_result(self, result: FuzzingResult):
        """Analyze a fuzzing result."""
        if result.vulnerability_indicators:
            logger.info(f"Vulnerability indicators: {result.vulnerability_indicators}")

        if result.unique_response:
            logger.debug(f"Unique response found: {result.status_code}")

    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Get status of a fuzzing session."""
        session = self.active_sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        elapsed_time = time.time() - session.start_time
        requests_per_second = session.total_requests / elapsed_time if elapsed_time > 0 else 0

        return {
            "session_id": session_id,
            "target_url": session.target_url,
            "strategy": session.strategy.value,
            "total_requests": session.total_requests,
            "max_requests": session.max_requests,
            "vulnerabilities_found": session.vulnerabilities_found,
            "unique_responses": session.unique_responses,
            "elapsed_time": elapsed_time,
            "requests_per_second": requests_per_second,
            "progress": (session.total_requests / session.max_requests) * 100
        }

    def stop_session(self, session_id: str) -> bool:
        """Stop a fuzzing session."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            logger.info(f"Stopped fuzzing session {session_id}")
            return True
        return False

    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """Get status of all active sessions."""
        return [self.get_session_status(sid) for sid in self.active_sessions.keys()]

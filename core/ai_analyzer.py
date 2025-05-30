"""
AI-powered response analysis module for intelligent vulnerability detection.

This module provides advanced AI capabilities for analyzing HTTP responses,
detecting patterns, and identifying potential security vulnerabilities
using machine learning and natural language processing.
"""

import re
import json
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from enum import Enum
import asyncio
import logging

try:
    import openai
    from transformers import pipeline, AutoTokenizer, AutoModel
    import torch
    from sentence_transformers import SentenceTransformer
except ImportError as e:
    logging.warning(f"AI dependencies not available: {e}")
    openai = None
    pipeline = None
    SentenceTransformer = None

from ..core.config import Config

logger = logging.getLogger(__name__)


class AnalysisType(Enum):
    """Types of AI analysis that can be performed."""
    VULNERABILITY_DETECTION = "vulnerability_detection"
    SENSITIVE_DATA_DETECTION = "sensitive_data_detection"
    ERROR_ANALYSIS = "error_analysis"
    PATTERN_RECOGNITION = "pattern_recognition"
    BUSINESS_LOGIC_ANALYSIS = "business_logic_analysis"


@dataclass
class AIAnalysisResult:
    """Result of AI analysis on HTTP response."""
    analysis_type: AnalysisType
    confidence: float
    findings: List[Dict[str, Any]]
    recommendations: List[str]
    metadata: Dict[str, Any]
    processing_time: float


@dataclass
class SensitiveDataMatch:
    """Detected sensitive data in response."""
    data_type: str
    pattern: str
    location: str
    confidence: float
    context: str


class AIResponseAnalyzer:
    """AI-powered HTTP response analyzer."""

    def __init__(self, config: Config):
        self.config = config
        self.openai_client = None
        self.sentiment_analyzer = None
        self.sentence_transformer = None
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.sensitive_data_patterns = self._load_sensitive_data_patterns()

        # Initialize AI models
        self._initialize_models()

    def _initialize_models(self):
        """Initialize AI models and clients."""
        try:
            # Initialize OpenAI client
            if hasattr(self.config, 'openai_api_key') and self.config.openai_api_key:
                if openai:
                    openai.api_key = self.config.openai_api_key
                    self.openai_client = openai
                    logger.info("OpenAI client initialized")

            # Initialize local models
            if pipeline:
                self.sentiment_analyzer = pipeline(
                    "sentiment-analysis",
                    model="distilbert-base-uncased-finetuned-sst-2-english"
                )
                logger.info("Sentiment analyzer initialized")

            if SentenceTransformer:
                self.sentence_transformer = SentenceTransformer('all-MiniLM-L6-v2')
                logger.info("Sentence transformer initialized")

        except Exception as e:
            logger.warning(f"Failed to initialize AI models: {e}")

    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load vulnerability detection patterns."""
        return {
            "sql_injection": [
                r"sql syntax.*error",
                r"mysql_fetch_array",
                r"ora-\d+",
                r"microsoft.*oledb.*error",
                r"unclosed quotation mark",
                r"syntax error.*near"
            ],
            "xss": [
                r"<script[^>]*>.*</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"eval\s*\(",
                r"document\.(cookie|location|write)"
            ],
            "path_traversal": [
                r"\.\./",
                r"\.\.\\",
                r"/etc/passwd",
                r"c:\\windows\\system32"
            ],
            "information_disclosure": [
                r"debug\s*=\s*true",
                r"stack trace",
                r"exception.*trace",
                r"internal server error",
                r"application error"
            ],
            "authentication_bypass": [
                r"admin.*panel",
                r"unauthorized.*access",
                r"session.*expired",
                r"invalid.*credentials",
                r"authentication.*failed"
            ]
        }

    def _load_sensitive_data_patterns(self) -> Dict[str, str]:
        """Load sensitive data detection patterns."""
        return {
            "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "phone": r"\b\d{3}-\d{3}-\d{4}\b",
            "api_key": r"(?:api[_-]?key|apikey)[\"'\s:=]+([a-z0-9]{20,})",
            "jwt_token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
            "private_key": r"-----BEGIN.*PRIVATE KEY-----",
            "password": r"(?:password|passwd|pwd)[\"'\s:=]+([^\s\"']{6,})"
        }

    async def analyze_response(
            self,
            response_data: Dict[str, Any],
            analysis_types: List[AnalysisType] = None
    ) -> List[AIAnalysisResult]:
        """
        Perform comprehensive AI analysis on HTTP response.
        
        Args:
            response_data: HTTP response data including headers, body, status
            analysis_types: Types of analysis to perform
            
        Returns:
            List of analysis results
        """
        if analysis_types is None:
            analysis_types = list(AnalysisType)

        results = []

        for analysis_type in analysis_types:
            try:
                start_time = asyncio.get_event_loop().time()

                if analysis_type == AnalysisType.VULNERABILITY_DETECTION:
                    result = await self._detect_vulnerabilities(response_data)
                elif analysis_type == AnalysisType.SENSITIVE_DATA_DETECTION:
                    result = await self._detect_sensitive_data(response_data)
                elif analysis_type == AnalysisType.ERROR_ANALYSIS:
                    result = await self._analyze_errors(response_data)
                elif analysis_type == AnalysisType.PATTERN_RECOGNITION:
                    result = await self._recognize_patterns(response_data)
                elif analysis_type == AnalysisType.BUSINESS_LOGIC_ANALYSIS:
                    result = await self._analyze_business_logic(response_data)
                else:
                    continue

                processing_time = asyncio.get_event_loop().time() - start_time
                result.processing_time = processing_time
                results.append(result)

            except Exception as e:
                logger.error(f"AI analysis failed for {analysis_type}: {e}")

        return results

    async def _detect_vulnerabilities(self, response_data: Dict[str, Any]) -> AIAnalysisResult:
        """Detect vulnerabilities using pattern matching and AI."""
        findings = []
        response_text = self._extract_response_text(response_data)

        # Pattern-based detection
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, response_text, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        "type": vuln_type,
                        "pattern": pattern,
                        "match": match.group(),
                        "location": f"Position {match.start()}-{match.end()}",
                        "confidence": 0.7,
                        "method": "pattern_matching"
                    })

        # AI-based detection using OpenAI
        if self.openai_client and len(response_text) < 8000:
            ai_findings = await self._openai_vulnerability_analysis(response_text)
            findings.extend(ai_findings)

        # Calculate overall confidence
        confidence = self._calculate_confidence(findings)

        recommendations = self._generate_vulnerability_recommendations(findings)

        return AIAnalysisResult(
            analysis_type=AnalysisType.VULNERABILITY_DETECTION,
            confidence=confidence,
            findings=findings,
            recommendations=recommendations,
            metadata={"total_patterns_checked": len(self.vulnerability_patterns)},
            processing_time=0.0
        )

    async def _detect_sensitive_data(self, response_data: Dict[str, Any]) -> AIAnalysisResult:
        """Detect sensitive data in response."""
        findings = []
        response_text = self._extract_response_text(response_data)

        for data_type, pattern in self.sensitive_data_patterns.items():
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                context = self._extract_context(response_text, match.start(), match.end())
                findings.append({
                    "data_type": data_type,
                    "pattern": pattern,
                    "match": match.group(),
                    "location": f"Position {match.start()}-{match.end()}",
                    "context": context,
                    "confidence": self._calculate_data_confidence(data_type, match.group()),
                    "risk_level": self._assess_data_risk(data_type)
                })

        confidence = self._calculate_confidence(findings)
        recommendations = self._generate_data_protection_recommendations(findings)

        return AIAnalysisResult(
            analysis_type=AnalysisType.SENSITIVE_DATA_DETECTION,
            confidence=confidence,
            findings=findings,
            recommendations=recommendations,
            metadata={"patterns_checked": len(self.sensitive_data_patterns)},
            processing_time=0.0
        )

    async def _analyze_errors(self, response_data: Dict[str, Any]) -> AIAnalysisResult:
        """Analyze error messages and stack traces."""
        findings = []
        response_text = self._extract_response_text(response_data)
        status_code = response_data.get('status_code', 200)

        # Check for error indicators
        error_indicators = [
            "error", "exception", "traceback", "stack trace",
            "internal server error", "debug", "warning"
        ]

        for indicator in error_indicators:
            if indicator.lower() in response_text.lower():
                context = self._extract_error_context(response_text, indicator)
                findings.append({
                    "type": "error_disclosure",
                    "indicator": indicator,
                    "context": context,
                    "status_code": status_code,
                    "confidence": 0.8,
                    "severity": self._assess_error_severity(indicator, context)
                })

        # AI-powered error analysis
        if self.openai_client and findings:
            ai_analysis = await self._openai_error_analysis(response_text, findings)
            findings.extend(ai_analysis)

        confidence = self._calculate_confidence(findings)
        recommendations = self._generate_error_recommendations(findings)

        return AIAnalysisResult(
            analysis_type=AnalysisType.ERROR_ANALYSIS,
            confidence=confidence,
            findings=findings,
            recommendations=recommendations,
            metadata={"status_code": status_code},
            processing_time=0.0
        )

    async def _recognize_patterns(self, response_data: Dict[str, Any]) -> AIAnalysisResult:
        """Recognize patterns using machine learning."""
        findings = []
        response_text = self._extract_response_text(response_data)

        # Use sentence transformer for similarity detection
        if self.sentence_transformer:
            patterns = await self._detect_similarity_patterns(response_text)
            findings.extend(patterns)

        # Statistical pattern analysis
        stats = self._analyze_response_statistics(response_data)
        findings.append({
            "type": "statistical_analysis",
            "statistics": stats,
            "anomalies": self._detect_statistical_anomalies(stats),
            "confidence": 0.6
        })

        confidence = self._calculate_confidence(findings)
        recommendations = ["Investigate unusual patterns", "Monitor for consistency"]

        return AIAnalysisResult(
            analysis_type=AnalysisType.PATTERN_RECOGNITION,
            confidence=confidence,
            findings=findings,
            recommendations=recommendations,
            metadata={"analysis_method": "ml_pattern_recognition"},
            processing_time=0.0
        )

    async def _analyze_business_logic(self, response_data: Dict[str, Any]) -> AIAnalysisResult:
        """Analyze business logic patterns and potential flaws."""
        findings = []
        response_text = self._extract_response_text(response_data)

        # Look for business logic indicators
        business_indicators = [
            "balance", "credit", "debit", "transaction", "payment",
            "order", "cart", "checkout", "user", "admin", "role",
            "permission", "access", "privilege"
        ]

        detected_indicators = []
        for indicator in business_indicators:
            if indicator.lower() in response_text.lower():
                detected_indicators.append(indicator)

        if detected_indicators:
            findings.append({
                "type": "business_logic_indicators",
                "indicators": detected_indicators,
                "confidence": 0.7,
                "potential_risks": self._assess_business_logic_risks(detected_indicators)
            })

        # AI-powered business logic analysis
        if self.openai_client and detected_indicators:
            ai_analysis = await self._openai_business_logic_analysis(response_text, detected_indicators)
            findings.extend(ai_analysis)

        confidence = self._calculate_confidence(findings)
        recommendations = self._generate_business_logic_recommendations(findings)

        return AIAnalysisResult(
            analysis_type=AnalysisType.BUSINESS_LOGIC_ANALYSIS,
            confidence=confidence,
            findings=findings,
            recommendations=recommendations,
            metadata={"indicators_found": len(detected_indicators)},
            processing_time=0.0
        )

    def _extract_response_text(self, response_data: Dict[str, Any]) -> str:
        """Extract text content from response data."""
        body = response_data.get('body', '')
        headers = response_data.get('headers', {})

        # Handle different content types
        content_type = headers.get('content-type', '').lower()

        if isinstance(body, bytes):
            try:
                body = body.decode('utf-8')
            except UnicodeDecodeError:
                body = body.decode('utf-8', errors='ignore')

        if 'json' in content_type:
            try:
                if isinstance(body, str):
                    json_data = json.loads(body)
                else:
                    json_data = body
                body = json.dumps(json_data, indent=2)
            except json.JSONDecodeError:
                pass

        # Include relevant headers in analysis
        header_text = '\n'.join([f"{k}: {v}" for k, v in headers.items()])

        return f"{header_text}\n\n{body}"

    def _extract_context(self, text: str, start: int, end: int, window: int = 100) -> str:
        """Extract context around a match."""
        context_start = max(0, start - window)
        context_end = min(len(text), end + window)
        return text[context_start:context_end]

    def _extract_error_context(self, text: str, indicator: str) -> str:
        """Extract context around error indicators."""
        pattern = re.compile(f".*{re.escape(indicator)}.*", re.IGNORECASE)
        matches = pattern.findall(text)
        return matches[0] if matches else ""

    def _calculate_confidence(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall confidence score."""
        if not findings:
            return 0.0

        confidences = [f.get('confidence', 0.5) for f in findings]
        return sum(confidences) / len(confidences)

    def _calculate_data_confidence(self, data_type: str, match: str) -> float:
        """Calculate confidence for sensitive data matches."""
        confidence_map = {
            "credit_card": 0.9,
            "ssn": 0.95,
            "email": 0.8,
            "phone": 0.7,
            "api_key": 0.85,
            "jwt_token": 0.95,
            "private_key": 0.99,
            "password": 0.6
        }
        return confidence_map.get(data_type, 0.5)

    def _assess_data_risk(self, data_type: str) -> str:
        """Assess risk level for data types."""
        high_risk = ["credit_card", "ssn", "private_key", "password"]
        medium_risk = ["api_key", "jwt_token"]

        if data_type in high_risk:
            return "HIGH"
        elif data_type in medium_risk:
            return "MEDIUM"
        else:
            return "LOW"

    def _assess_error_severity(self, indicator: str, context: str) -> str:
        """Assess severity of error disclosure."""
        high_severity = ["stack trace", "traceback", "debug"]
        medium_severity = ["internal server error", "exception"]

        if any(h in indicator.lower() for h in high_severity):
            return "HIGH"
        elif any(m in indicator.lower() for m in medium_severity):
            return "MEDIUM"
        else:
            return "LOW"

    def _assess_business_logic_risks(self, indicators: List[str]) -> List[str]:
        """Assess potential business logic risks."""
        risks = []

        financial_terms = ["balance", "credit", "debit", "transaction", "payment"]
        auth_terms = ["admin", "role", "permission", "access", "privilege"]

        if any(term in indicators for term in financial_terms):
            risks.append("Financial data exposure")
            risks.append("Transaction manipulation risk")

        if any(term in indicators for term in auth_terms):
            risks.append("Authorization bypass potential")
            risks.append("Privilege escalation risk")

        return risks

    def _analyze_response_statistics(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze statistical properties of response."""
        body = self._extract_response_text(response_data)

        return {
            "length": len(body),
            "word_count": len(body.split()),
            "unique_chars": len(set(body)),
            "entropy": self._calculate_entropy(body),
            "json_fields": self._count_json_fields(body),
            "status_code": response_data.get('status_code', 200)
        }

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        entropy = 0.0
        text_len = len(text)

        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * (probability.bit_length() - 1)

        return entropy

    def _count_json_fields(self, text: str) -> int:
        """Count JSON fields in response."""
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return len(data)
            elif isinstance(data, list) and data and isinstance(data[0], dict):
                return len(data[0])
        except (json.JSONDecodeError, IndexError, TypeError):
            pass
        return 0

    def _detect_statistical_anomalies(self, stats: Dict[str, Any]) -> List[str]:
        """Detect statistical anomalies."""
        anomalies = []

        if stats['entropy'] < 2.0:
            anomalies.append("Low entropy content")
        elif stats['entropy'] > 6.0:
            anomalies.append("High entropy content (possible encryption)")

        if stats['length'] > 100000:
            anomalies.append("Unusually large response")
        elif stats['length'] < 10:
            anomalies.append("Unusually small response")

        return anomalies

    async def _detect_similarity_patterns(self, text: str) -> List[Dict[str, Any]]:
        """Detect similarity patterns using sentence transformers."""
        findings = []

        if not self.sentence_transformer:
            return findings

        try:
            # Split text into sentences
            sentences = re.split(r'[.!?]+', text)
            sentences = [s.strip() for s in sentences if len(s.strip()) > 10]

            if len(sentences) < 2:
                return findings

            # Calculate embeddings
            embeddings = self.sentence_transformer.encode(sentences)

            # Find similar sentences
            similarities = []
            for i in range(len(sentences)):
                for j in range(i + 1, len(sentences)):
                    similarity = torch.cosine_similarity(
                        torch.tensor(embeddings[i]).unsqueeze(0),
                        torch.tensor(embeddings[j]).unsqueeze(0)
                    ).item()

                    if similarity > 0.8:  # High similarity threshold
                        similarities.append({
                            "sentence1": sentences[i],
                            "sentence2": sentences[j],
                            "similarity": similarity
                        })

            if similarities:
                findings.append({
                    "type": "high_similarity_content",
                    "similarities": similarities,
                    "confidence": 0.7
                })

        except Exception as e:
            logger.error(f"Similarity detection failed: {e}")

        return findings

    async def _openai_vulnerability_analysis(self, text: str) -> List[Dict[str, Any]]:
        """Use OpenAI for vulnerability analysis."""
        findings = []

        try:
            prompt = f"""
            Analyze the following HTTP response for potential security vulnerabilities.
            Look for signs of:
            - SQL injection vulnerabilities
            - Cross-site scripting (XSS)
            - Information disclosure
            - Authentication bypasses
            - Authorization flaws
            
            Response content:
            {text[:4000]}
            
            Provide a JSON response with findings including type, description, and confidence (0-1).
            """

            response = await self.openai_client.ChatCompletion.acreate(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.1
            )

            content = response.choices[0].message.content
            # Parse AI response (simplified - would need more robust parsing)
            if "vulnerability" in content.lower():
                findings.append({
                    "type": "ai_detected_vulnerability",
                    "description": content,
                    "confidence": 0.6,
                    "method": "openai_analysis"
                })

        except Exception as e:
            logger.error(f"OpenAI vulnerability analysis failed: {e}")

        return findings

    async def _openai_error_analysis(self, text: str, findings: List[Dict]) -> List[Dict[str, Any]]:
        """Use OpenAI for error analysis."""
        ai_findings = []

        try:
            prompt = f"""
            Analyze the following error messages for security implications:
            
            {text[:2000]}
            
            Identify:
            - Information disclosure risks
            - Framework/technology stack details
            - Potential attack vectors
            - Recommended mitigations
            
            Provide concise analysis.
            """

            response = await self.openai_client.ChatCompletion.acreate(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
                temperature=0.1
            )

            content = response.choices[0].message.content
            ai_findings.append({
                "type": "ai_error_analysis",
                "analysis": content,
                "confidence": 0.7,
                "method": "openai_analysis"
            })

        except Exception as e:
            logger.error(f"OpenAI error analysis failed: {e}")

        return ai_findings

    async def _openai_business_logic_analysis(self, text: str, indicators: List[str]) -> List[Dict[str, Any]]:
        """Use OpenAI for business logic analysis."""
        ai_findings = []

        try:
            prompt = f"""
            Analyze the following API response for business logic vulnerabilities.
            
            Detected business indicators: {', '.join(indicators)}
            
            Response content:
            {text[:3000]}
            
            Look for:
            - Insecure direct object references
            - Business flow bypass opportunities
            - Privilege escalation vectors
            - Data manipulation risks
            
            Provide specific findings with risk assessment.
            """

            response = await self.openai_client.ChatCompletion.acreate(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=800,
                temperature=0.1
            )

            content = response.choices[0].message.content
            ai_findings.append({
                "type": "ai_business_logic_analysis",
                "analysis": content,
                "indicators": indicators,
                "confidence": 0.65,
                "method": "openai_analysis"
            })

        except Exception as e:
            logger.error(f"OpenAI business logic analysis failed: {e}")

        return ai_findings

    def _generate_vulnerability_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate recommendations for vulnerability findings."""
        recommendations = []

        vuln_types = set(f.get('type', '') for f in findings)

        if 'sql_injection' in vuln_types:
            recommendations.append("Implement parameterized queries and input validation")

        if 'xss' in vuln_types:
            recommendations.append("Apply output encoding and CSP headers")

        if 'information_disclosure' in vuln_types:
            recommendations.append("Disable debug mode and error disclosure in production")

        if 'authentication_bypass' in vuln_types:
            recommendations.append("Review authentication mechanisms and session management")

        return recommendations

    def _generate_data_protection_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate data protection recommendations."""
        recommendations = []

        data_types = set(f.get('data_type', '') for f in findings)

        if any(dt in data_types for dt in ['credit_card', 'ssn']):
            recommendations.append("Implement PCI DSS compliance measures")
            recommendations.append("Encrypt sensitive data at rest and in transit")

        if 'api_key' in data_types or 'jwt_token' in data_types:
            recommendations.append("Rotate API keys and tokens regularly")
            recommendations.append("Implement token expiration and revocation")

        if 'email' in data_types:
            recommendations.append("Consider GDPR/privacy compliance requirements")

        return recommendations

    def _generate_error_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate error handling recommendations."""
        recommendations = [
            "Implement custom error pages for production",
            "Log detailed errors server-side only",
            "Use generic error messages for client responses",
            "Implement proper exception handling"
        ]
        return recommendations

    def _generate_business_logic_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate business logic security recommendations."""
        recommendations = [
            "Implement proper authorization checks",
            "Validate business rules server-side",
            "Use indirect object references",
            "Implement audit logging for sensitive operations",
            "Test business flow edge cases"
        ]
        return recommendations


class VulnerabilityChainer:
    """Automatically chain vulnerabilities for maximum impact."""

    def __init__(self, ai_analyzer: AIResponseAnalyzer):
        self.ai_analyzer = ai_analyzer
        self.vulnerability_graph = {}
        self.exploitation_chains = []

    async def build_exploitation_chains(
            self,
            vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Build exploitation chains from discovered vulnerabilities.
        
        Args:
            vulnerabilities: List of discovered vulnerabilities
            
        Returns:
            List of exploitation chains with impact assessment
        """
        chains = []

        # Group vulnerabilities by endpoint
        endpoint_vulns = self._group_by_endpoint(vulnerabilities)

        # Build chains for each endpoint
        for endpoint, vulns in endpoint_vulns.items():
            endpoint_chains = await self._build_endpoint_chains(endpoint, vulns)
            chains.extend(endpoint_chains)

        # Build cross-endpoint chains
        cross_chains = await self._build_cross_endpoint_chains(vulnerabilities)
        chains.extend(cross_chains)

        # Rank chains by impact
        ranked_chains = self._rank_chains_by_impact(chains)

        return ranked_chains

    def _group_by_endpoint(self, vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
        """Group vulnerabilities by endpoint."""
        grouped = {}
        for vuln in vulnerabilities:
            endpoint = vuln.get('endpoint', 'unknown')
            if endpoint not in grouped:
                grouped[endpoint] = []
            grouped[endpoint].append(vuln)
        return grouped

    async def _build_endpoint_chains(self, endpoint: str, vulns: List[Dict]) -> List[Dict]:
        """Build exploitation chains for a single endpoint."""
        chains = []

        # Look for common chain patterns
        auth_bypass = [v for v in vulns if 'auth' in v.get('type', '').lower()]
        bola_vulns = [v for v in vulns if 'bola' in v.get('type', '').lower()]
        injection_vulns = [v for v in vulns if 'injection' in v.get('type', '').lower()]

        # Auth bypass + BOLA chain
        if auth_bypass and bola_vulns:
            chains.append({
                "type": "auth_bypass_to_bola",
                "steps": auth_bypass + bola_vulns,
                "impact": "HIGH",
                "description": "Authentication bypass leading to unauthorized data access"
            })

        # Injection + privilege escalation
        if injection_vulns:
            chains.append({
                "type": "injection_escalation",
                "steps": injection_vulns,
                "impact": "CRITICAL",
                "description": "SQL injection potentially leading to database compromise"
            })

        return chains

    async def _build_cross_endpoint_chains(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Build chains across multiple endpoints."""
        chains = []

        # Look for information disclosure + authentication bypass
        info_disclosure = [v for v in vulnerabilities if 'disclosure' in v.get('type', '')]
        auth_vulns = [v for v in vulnerabilities if 'auth' in v.get('type', '')]

        if info_disclosure and auth_vulns:
            chains.append({
                "type": "info_disclosure_to_auth_bypass",
                "steps": info_disclosure + auth_vulns,
                "impact": "HIGH",
                "description": "Information disclosure enabling authentication bypass"
            })

        return chains

    def _rank_chains_by_impact(self, chains: List[Dict]) -> List[Dict]:
        """Rank exploitation chains by potential impact."""
        impact_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        return sorted(
            chains,
            key=lambda x: impact_scores.get(x.get('impact', 'LOW'), 1),
            reverse=True
        )

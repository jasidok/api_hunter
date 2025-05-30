"""
API Hunter - Vulnerability Detection Module

This module contains various vulnerability detectors for identifying security flaws
in APIs including OWASP API Top 10 vulnerabilities and beyond.
"""

from .base_detector import BaseVulnerabilityDetector, VulnerabilityResult, Severity
from .bola_detector import BOLADetector
from .bfla_detector import BFLADetector
from .mass_assignment import MassAssignmentDetector
from .injection_tester import InjectionTester
from .ssrf_detector import SSRFDetector
from .business_logic import BusinessLogicDetector
from .rate_limit_bypass import RateLimitBypassDetector
from .parameter_pollution import ParameterPollutionDetector

__all__ = [
    'BaseVulnerabilityDetector',
    'VulnerabilityResult',
    'Severity',
    'BOLADetector',
    'BFLADetector',
    'MassAssignmentDetector',
    'InjectionTester',
    'SSRFDetector',
    'BusinessLogicDetector',
    'RateLimitBypassDetector',
    'ParameterPollutionDetector',
]

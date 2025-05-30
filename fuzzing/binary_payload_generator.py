"""
Binary Payload Generator for API Hunter

This module provides advanced binary payload generation capabilities using
template-based syntax for protocol fuzzing and binary API testing.

Based on the excellent work by Stefano Di Paola (@WisecWisec) from IMQ Mindedsecurity.
Original implementation: simple_payload_generator.py
"""

import itertools
import struct
import random
import logging
from typing import Iterator, List, Union, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class BinaryPayloadGenerator:
    """
    Advanced binary payload generator using template syntax.
    
    Template Format:
    Use dynamic data between brackets {}
    - Dynamic payload expects R[min,max,'B|H'] for range interval data
    - Simple array [00,0B,0A] to generate discrete bytes
    - Random bytes r[length,count] for random data generation
    - File input @filename to load payloads from file
    
    All constants are considered in hexadecimal format (00 - FF)
    
    Example:
    '{[0,1]}0A{R[0,1,"B"]}FF{R[1,2,">H"]}0E{[0,4]}DD'
    
    Will generate multiple payloads with combinations of:
    - [0,1] at position 1
    - R[0,1,"B"] as single byte 0-1
    - FF as constant
    - R[1,2,">H"] as big-endian short 1-2
    - 0E as constant
    - [0,4] at final position
    - DD as constant
    """

    def __init__(self, template: str, loop_on_first: bool = False):
        """
        Initialize the binary payload generator.
        
        Args:
            template: Template string with placeholder syntax
            loop_on_first: Whether to reverse the iteration order
        """
        self.template = template
        self.loop_on_first = loop_on_first
        self.generated_payloads = None
        self._generate()

    def parse_data(self, data: str) -> Any:
        """Parse data specification safely."""
        try:
            # Use ast.literal_eval for safer evaluation
            import ast
            return ast.literal_eval(data)
        except (ValueError, SyntaxError):
            # Fallback to eval for complex expressions (with caution)
            logger.warning(f"Using eval() for parsing: {data}")
            return eval(data)

    def create_range_pack(self, values: List[Union[int, str]]) -> List[bytes]:
        """
        Create packed byte array from range specification.
        
        Args:
            values: [min, max, format] where format is struct format string
            
        Returns:
            List of packed byte values
        """
        try:
            return [struct.pack(values[2], num) for num in range(values[0], values[1] + 1)]
        except struct.error as e:
            logger.error(f"Struct packing error with values {values}: {e}")
            return [b'\x00']

    def create_bytes_array(self, values: List[int]) -> List[bytes]:
        """
        Create byte array from list of integer values.
        
        Args:
            values: List of integer values (0-255)
            
        Returns:
            List of packed bytes
        """
        try:
            return [struct.pack('B', el) for el in values if 0 <= el <= 255]
        except struct.error as e:
            logger.error(f"Byte packing error with values {values}: {e}")
            return [b'\x00']

    def create_random_bytes(self, values: List[int]) -> List[bytes]:
        """
        Create random byte sequences.
        
        Args:
            values: [length, count] - length of each sequence, number of sequences
            
        Returns:
            List of random byte sequences
        """
        try:
            length, count = values
            return [random.randbytes(length) for _ in range(count)]
        except (ValueError, TypeError) as e:
            logger.error(f"Random bytes generation error with values {values}: {e}")
            return [b'\x00']

    def create_list_from_file(self, file_name: str) -> Iterator[bytes]:
        """
        Load payloads from file.
        
        Args:
            file_name: Path to file containing payloads (one per line)
            
        Returns:
            Iterator of byte payloads
        """
        try:
            file_path = Path(file_name.strip())
            if not file_path.exists():
                logger.error(f"Payload file not found: {file_path}")
                return iter([b''])

            def file_iterator():
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            # Try to decode as hex, fallback to ASCII
                            try:
                                if all(c in '0123456789abcdefABCDEF' for c in line.replace(' ', '')):
                                    yield bytes.fromhex(line.replace(' ', ''))
                                else:
                                    yield line.encode('ascii')
                            except ValueError:
                                yield line.encode('ascii')

            return file_iterator()
        except Exception as e:
            logger.error(f"File loading error for {file_name}: {e}")
            return iter([b''])

    def _generate(self) -> None:
        """Generate the payload combinations from template."""
        try:
            parts = self.template.split('{')
            packed_values = []

            for part in parts:
                if '}' in part:
                    spec, rest = part.split('}', 1)
                    if not spec:
                        continue

                    first_char = spec[0]

                    if first_char == 'R':  # Range: {R[1,4,'B']}
                        values = self.parse_data(spec[1:])
                        packed_values.append(self.create_range_pack(values))

                    elif first_char == 'r':  # Random bytes: {r[2,4]}
                        values = self.parse_data(spec[1:])
                        packed_values.append(self.create_random_bytes(values))

                    elif first_char == '[':  # Array: {[0,1,2,3]}
                        values = self.parse_data(spec)
                        packed_values.append(self.create_bytes_array(values))

                    elif first_char == '@':  # File: {@payloads.txt}
                        file_payloads = list(self.create_list_from_file(spec[1:]))
                        packed_values.append(file_payloads)

                    else:
                        logger.warning(f'Unknown specification: {spec}')
                        packed_values.append([b'\x00'])

                    # Add the rest as hex
                    if rest:
                        try:
                            packed_values.append([bytes.fromhex(rest)])
                        except ValueError:
                            logger.warning(f"Invalid hex data: {rest}")
                            packed_values.append([b''])
                else:
                    # Plain hex data
                    if part:
                        try:
                            packed_values.append([bytes.fromhex(part)])
                        except ValueError:
                            logger.warning(f"Invalid hex data: {part}")
                            packed_values.append([b''])

            if self.loop_on_first:
                packed_values.reverse()

            self.generated_payloads = itertools.product(*packed_values)

        except Exception as e:
            logger.error(f"Template generation error: {e}")
            self.generated_payloads = iter([b''])

    def __iter__(self) -> Iterator[bytes]:
        """Make the generator iterable."""
        return self

    def __next__(self) -> bytes:
        """Get the next payload."""
        return self.get_next()

    def get_next(self) -> bytes:
        """
        Get the next generated payload.
        
        Returns:
            Next payload as bytes
        """
        try:
            payload_parts = next(self.generated_payloads)
            if self.loop_on_first:
                return b''.join(payload_parts[::-1])
            return b''.join(payload_parts)
        except StopIteration:
            raise StopIteration("No more payloads available")

    def generate_all(self, max_count: int = 10000) -> List[bytes]:
        """
        Generate all payloads up to max_count.
        
        Args:
            max_count: Maximum number of payloads to generate
            
        Returns:
            List of generated payloads
        """
        payloads = []
        count = 0

        try:
            for payload in self:
                payloads.append(payload)
                count += 1
                if count >= max_count:
                    logger.warning(f"Reached maximum payload count: {max_count}")
                    break
        except StopIteration:
            pass

        return payloads

    def reset(self) -> None:
        """Reset the generator to start from the beginning."""
        self._generate()


# Integration with existing PayloadGenerator
class EnhancedPayloadGenerator:
    """
    Enhanced payload generator that combines text-based and binary payloads.
    """

    def __init__(self, config=None):
        self.config = config
        from .payload_generator import PayloadGenerator
        self.text_generator = PayloadGenerator(config)

    def generate_binary_payloads(self, template: str, max_count: int = 1000) -> List[bytes]:
        """
        Generate binary payloads from template.
        
        Args:
            template: Binary payload template
            max_count: Maximum payloads to generate
            
        Returns:
            List of binary payloads
        """
        generator = BinaryPayloadGenerator(template)
        return generator.generate_all(max_count)

    def generate_protocol_payloads(self, protocol: str) -> List[bytes]:
        """
        Generate protocol-specific binary payloads.
        
        Args:
            protocol: Protocol name (e.g., 'grpc', 'websocket', 'custom')
            
        Returns:
            List of protocol-specific payloads
        """
        templates = {
            'grpc': [
                # gRPC frame header fuzzing
                '{R[0,255,"B"]}{R[0,4,"I"]}{r[10,5]}',
                # Length field fuzzing
                '{[0,1,2,3,4]}{R[1,65535,">H"]}{r[5,3]}'
            ],
            'websocket': [
                # WebSocket frame fuzzing
                '{[129,130,131,132]}{R[0,127,"B"]}{r[4,1]}{r[10,5]}',
                # Payload length variants
                '{[129]}{[126]}{R[1,65535,">H"]}{r[8,3]}'
            ],
            'custom': [
                # Generic binary protocol fuzzing
                '{R[0,255,"B"]}{R[0,65535,">H"]}{r[20,5]}',
                '{[0,1,2,4,8,16,32,64,128,255]}{r[50,3]}'
            ]
        }

        protocol_templates = templates.get(protocol.lower(), templates['custom'])
        all_payloads = []

        for template in protocol_templates:
            generator = BinaryPayloadGenerator(template)
            payloads = generator.generate_all(500)  # Limit per template
            all_payloads.extend(payloads)

        return all_payloads

    async def generate_hybrid_payloads(self, context: dict) -> List[Union[str, bytes]]:
        """
        Generate both text and binary payloads based on context.
        
        Args:
            context: Analysis context from endpoint discovery
            
        Returns:
            Mixed list of text and binary payloads
        """
        payloads = []

        # Generate text payloads
        text_payloads = await self.text_generator.generate_all_payloads()
        payloads.extend(text_payloads)

        # Generate binary payloads based on context
        if context.get('content_type') == 'application/grpc':
            binary_payloads = self.generate_protocol_payloads('grpc')
            payloads.extend(binary_payloads)

        elif 'websocket' in context.get('technology', '').lower():
            binary_payloads = self.generate_protocol_payloads('websocket')
            payloads.extend(binary_payloads)

        else:
            # Generic binary fuzzing
            binary_payloads = self.generate_protocol_payloads('custom')
            payloads.extend(binary_payloads[:100])  # Limit for HTTP APIs

        return payloads


# Example templates for common protocols
COMMON_TEMPLATES = {
    'buffer_overflow': '{r[{size},1]}',  # Variable size random data
    'format_string': '{[@format_strings.txt]}',  # Load from file
    'integer_overflow': '{R[0,4294967295,"I"]}{R[0,65535,"H"]}{R[0,255,"B"]}',
    'magic_numbers': '{[0x7f,0x45,0x4c,0x46]}{r[50,1]}',  # ELF header + random
    'protocol_header': '{[0x01,0x02]}{R[1,1024,"H"]}{r[10,5]}',  # Version + length + data
}

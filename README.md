# API Hunter

> Advanced Bug Bounty Tool for API Security Testing

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)](https://github.com/api-hunter/api-hunter)

API Hunter is a comprehensive, AI-powered bug bounty hunting tool specifically designed for discovering and exploiting
vulnerabilities in modern APIs. Unlike basic endpoint enumerators, API Hunter focuses on sophisticated attack vectors,
business logic flaws, and complex vulnerability chains commonly found in real-world API implementations.

## 🎯 Features

### Core Capabilities

- **🔍 Intelligent API Discovery**: OpenAPI/Swagger, GraphQL, WSDL, gRPC schema discovery
- **🛡️ OWASP API Top 10 Testing**: Complete coverage of OWASP API security risks
- **🔐 Advanced Authentication Testing**: JWT, OAuth, API keys, session management
- **🧠 AI-Powered Analysis**: ML-driven vulnerability detection and response analysis
- **⚡ High-Performance Scanning**: Async processing with intelligent rate limiting
- **📊 Professional Reporting**: Executive and technical reports in multiple formats

### Vulnerability Detection

- **BOLA/IDOR** (Broken Object Level Authorization)
- **BFLA** (Broken Function Level Authorization)
- **Mass Assignment** vulnerabilities
- **JWT Security** flaws (weak secrets, algorithm confusion)
- **OAuth/OIDC** implementation flaws
- **GraphQL** specific vulnerabilities
- **Business Logic** bypass scenarios
- **Parameter Pollution** and Hidden Parameter Discovery
- **Injection** attacks (SQL, NoSQL, LDAP, etc.)
- **SSRF** via API parameters

### Advanced Features

- **Attack Chain Automation**: Automatic vulnerability chaining
- **Real-time Monitoring**: Continuous API change detection
- **Plugin System**: Extensible architecture with custom plugins
- **Burp Suite Integration**: Seamless workflow integration
- **Team Collaboration**: Multi-user support with shared workspaces

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/api-hunter/api-hunter.git
cd api-hunter

# Install dependencies
pip install -r requirements.txt

# Install API Hunter
pip install -e .
```

### Basic Usage

```bash
# Quick discovery scan
api-hunter scan https://api.example.com

# Full security assessment
api-hunter scan https://api.example.com --scan-type full --output results.json

# Custom scan with authentication
api-hunter scan https://api.example.com \
  --auth-token "Bearer your-token-here" \
  --scan-type auth \
  --threads 20 \
  --rate-limit 50

# GraphQL-specific testing
api-hunter scan https://api.example.com/graphql \
  --scan-type discovery \
  --format html \
  --output graphql-report.html
```

### Configuration

```bash
# View current configuration
api-hunter config

# Available plugins
api-hunter plugins --list-plugins

# Enable AI analysis
api-hunter plugins --enable ai_analysis
```

## 📖 Documentation

### Command Line Options

```
Usage: api-hunter scan [OPTIONS] TARGET_URL

Options:
  --scan-type [discovery|full|auth|fuzzing|custom]
                                  Type of scan to perform  [default: discovery]
  -o, --output TEXT               Output file for results
  --format [json|html|pdf|csv]    Output format  [default: json]
  -t, --threads INTEGER           Number of concurrent threads  [default: 10]
  --timeout INTEGER               Request timeout in seconds  [default: 30]
  --rate-limit INTEGER            Requests per second  [default: 10]
  --proxy TEXT                    Proxy URL (e.g., http://localhost:8080)
  --headers TEXT                  Custom headers (format: "Name: Value")
  --auth-token TEXT               Authentication token
  --auth-header TEXT              Authentication header name  [default: Authorization]
  --wordlist TEXT                 Custom wordlist file
  --max-depth INTEGER             Maximum directory depth for discovery  [default: 3]
  --quiet / -q                    Quiet mode (minimal output)
  --verbose / -v                  Verbose output
  --help                          Show this message and exit.
```

### Scan Types

- **discovery**: Basic endpoint discovery and technology fingerprinting
- **full**: Comprehensive security assessment including all vulnerability classes
- **auth**: Focus on authentication and authorization flaws
- **fuzzing**: Deep parameter fuzzing and input validation testing
- **custom**: Custom scan configuration based on provided wordlists and rules

### Configuration File

Create `.env` file in your project directory:

```env
# Database Configuration
DATABASE_URL=postgresql://localhost:5432/api_hunter
REDIS_URL=redis://localhost:6379/0

# Scanning Configuration
MAX_CONCURRENT_REQUESTS=50
REQUEST_TIMEOUT=30
RATE_LIMIT=100

# AI Configuration
OPENAI_API_KEY=your-openai-api-key
ENABLE_AI_ANALYSIS=true

# Security Configuration
VERIFY_SSL=false
PROXY_URL=http://localhost:8080

# Reporting Configuration
REPORT_OUTPUT_DIR=./reports
INCLUDE_EVIDENCE=true
```

## 🔧 Advanced Usage

### Programmatic API

```python
from api_hunter import APIHunter
from api_hunter.core.config import Config

# Initialize scanner
scanner = APIHunter(
    target_url="https://api.example.com",
    config=Config()
)

# Run discovery scan
results = await scanner.discover()

# Run full security assessment
vulnerabilities = await scanner.scan_vulnerabilities()

# Generate professional report
report = scanner.generate_report(
    format="html",
    include_evidence=True
)
```

### Custom Plugins

```python
from api_hunter.plugins.base_plugin import BasePlugin

class CustomVulnScanner(BasePlugin):
    name = "custom_vuln_scanner"
    description = "Custom vulnerability detection"
    
    async def scan(self, endpoint):
        # Custom scanning logic
        if self.detect_custom_vuln(endpoint):
            return self.create_vulnerability(
                title="Custom Vulnerability",
                severity="high",
                description="Custom vulnerability description"
            )
```

### Integration Examples

#### Burp Suite Integration

```bash
# Start API Hunter with Burp proxy
api-hunter scan https://api.example.com \
  --proxy http://localhost:8080 \
  --scan-type full
```

#### CI/CD Pipeline Integration

```yaml
# .github/workflows/api-security.yml
- name: API Security Scan
  run: |
    api-hunter scan ${{ env.API_URL }} \
      --format json \
      --output api-security-results.json \
      --quiet
    
    # Process results and fail if critical vulnerabilities found
    python process_results.py api-security-results.json
```

## 🛠️ Development

### Setting up Development Environment

```bash
# Clone repository
git clone https://github.com/api-hunter/api-hunter.git
cd api-hunter

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black .

# Type checking
mypy api_hunter/
```

### Project Structure

```
api_hunter/
├── core/                 # Core functionality
│   ├── config.py        # Configuration management
│   ├── logger.py        # Logging system
│   └── http_client.py   # HTTP client with rate limiting
├── discovery/           # API discovery engines
├── auth/               # Authentication testing
├── vulnerabilities/    # Vulnerability detection
├── fuzzing/           # Fuzzing engines
├── reporting/         # Report generation
├── plugins/           # Plugin system
├── database/          # Database models
├── tests/            # Test suite
└── main.py           # CLI entry point
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for your changes
5. Ensure all tests pass (`pytest`)
6. Format your code (`black .`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## 📋 Roadmap

### Phase 1: Core Infrastructure ✅

- [x] Project structure and configuration
- [x] CLI framework with rich output
- [x] HTTP client with rate limiting
- [x] Logging and error handling

### Phase 2: Discovery Engine 🚧

- [ ] OpenAPI/Swagger discovery
- [ ] GraphQL introspection
- [ ] Technology fingerprinting
- [ ] Documentation scraping

### Phase 3: Vulnerability Detection 📋

- [ ] BOLA/IDOR detection
- [ ] Authentication bypass testing
- [ ] Mass assignment discovery
- [ ] Business logic testing

### Phase 4: Advanced Features 📋

- [ ] AI-powered analysis
- [ ] Attack chain automation
- [ ] Professional reporting
- [ ] Plugin ecosystem

## ⚠️ Legal Disclaimer

API Hunter is designed for authorized security testing only. Users are responsible for ensuring they have proper
authorization before testing any systems. The developers assume no liability for misuse of this tool.

**Always ensure you have explicit permission before testing any API or system.**

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP API Security Project](https://owasp.org/www-project-api-security/) for security guidelines
- [Rich](https://github.com/Textualize/rich) for beautiful terminal output
- [httpx](https://github.com/encode/httpx) for async HTTP capabilities
- The security research community for continuous inspiration

## 📞 Support

- 📧 Email: contact@apihunter.io
- 🐛 Bug Reports: [GitHub Issues](https://github.com/api-hunter/api-hunter/issues)
- 💬 Discord: [API Hunter Community](https://discord.gg/api-hunter)
- 📖 Documentation: [Read the Docs](https://api-hunter.readthedocs.io/)

---

**Built with ❤️ for the security community**
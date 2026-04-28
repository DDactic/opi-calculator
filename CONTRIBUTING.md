# Contributing to OPI Calculator

We welcome contributions. Here's how to get started.

## Ways to Contribute

- **Report issues** - bugs, inconsistencies, unclear documentation
- **Add examples** - real-world scoring scenarios
- **Improve scoring** - propose weight adjustments or new sub-components
- **Add implementations** - port to other languages (Go, Rust, etc.)
- **Review PRs** - help review proposed changes

## Development Setup

### Python

```bash
cd python
pip install -e .
pip install pytest
pytest tests/ -v
```

### JavaScript

```bash
cd js
node -e "const {calculateOPI} = require('./opi-calculator'); console.log(calculateOPI({assets: [{fqdn: 'test.com', cdn: true, waf: true, originHidden: true}], cdnQuality: 'standard'}))"
```

## Pull Request Process

1. Fork the repo and create a branch
2. Make your changes
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a PR with a clear description

## Scoring Changes

Changes to weights, formulas, or component definitions are significant. Please:

1. Open an issue first to discuss the rationale
2. Include data or research supporting the change
3. Show impact on example scenarios (before/after scores)
4. Allow time for community feedback

## Code Style

- Python: follow PEP 8, type hints for public functions
- JavaScript: no dependencies, CommonJS + browser compatible
- Keep implementations functionally equivalent across languages

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

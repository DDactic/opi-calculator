# OPI Calculator

**Open Protection Index - DDoS resilience scoring**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-green.svg)](python/)
[![Node.js](https://img.shields.io/badge/Node.js-16+-green.svg)](js/)

OPI is a vendor-neutral, open standard for measuring how well a website or application can withstand DDoS attacks. This repo provides reference implementations in Python and JavaScript.

## What OPI Measures

| Component | Weight | What It Measures |
|-----------|--------|------------------|
| Defense Coverage | 20% | CDN, WAF, origin protection, rate limiting, automation |
| L7 Attack Resilience | 25% | HTTP floods, Slowloris, cache bypass, API abuse. v1.1: Penalized for exposed GraphQL, missing rate limiting, XMLRPC amplification, large API surface |
| L3/L4 Resilience | 15% | SYN/UDP floods, scrubbing centers, pipeline capacity |
| Protocol Resilience | 15% | HTTP/2 Rapid Reset, CONTINUATION Flood, QUIC attacks |
| Operational Resilience | 15% | Availability, latency, false positive rate, recovery |
| Evasion Resistance | 10% | JA3/JA4 detection, behavioral analysis, slow-rate |

## Grade Scale

| Score | Grade | Meaning |
|-------|-------|---------|
| 90-100 | A | Excellent - Enterprise-grade protection |
| 80-89 | B | Good - Solid defenses with minor gaps |
| 70-79 | C | Adequate - Basic protection, some risks |
| 60-69 | D | Poor - Major vulnerabilities |
| 0-59 | F | Critical - Minimal to no protection |

## Quick Start

### Python

```bash
cd python
pip install -e .

# Run example scenarios
opi-calc --example

# Score from asset inventory
opi-calc --assets ../examples/basic_assessment.json

# Interactive mode
opi-calc --interactive

# JSON output
opi-calc --assets ../examples/enterprise_stack.json --json
```

### Python Library

```python
from opi_calculator import calculate_opi

result = calculate_opi(
    assets=[
        {"fqdn": "www.example.com", "cdn": True, "waf": True,
         "origin_hidden": True, "vendor": "cloudflare", "rate_limiting": True},
        {"fqdn": "api.example.com", "cdn": True, "waf": False,
         "origin_hidden": False, "vendor": "cloudflare"},
        {"fqdn": "mail.example.com", "cdn": False, "waf": False,
         "origin_hidden": False},
    ],
    cdn_quality="standard",
)

print(f"OPI: {result['score']}/100 (Grade {result['grade']})")
# OPI: 47/100 (Grade F)

# Component breakdown
for name, comp in result["components"].items():
    print(f"  {name}: {comp['score']}/100")
```

### JavaScript / Node.js

```javascript
const { calculateOPI } = require('./js/opi-calculator');

const result = calculateOPI({
  assets: [
    { fqdn: 'www.example.com', cdn: true, waf: true,
      originHidden: true, vendor: 'cloudflare', rateLimiting: true },
    { fqdn: 'api.example.com', cdn: true, waf: false,
      originHidden: false, vendor: 'cloudflare' },
    { fqdn: 'mail.example.com', cdn: false, waf: false },
  ],
  cdnQuality: 'standard',
});

console.log(`OPI: ${result.score}/100 (Grade ${result.grade})`);
```

### Browser

```html
<script src="js/opi-calculator.js"></script>
<script>
  const result = OPICalculator.calculateOPI({
    assets: [
      { fqdn: 'app.example.com', cdn: true, waf: true, originHidden: true, vendor: 'cloudflare' },
    ],
    cdnQuality: 'enterprise',
  });
  document.getElementById('score').textContent = `${result.score}/100 (${result.grade})`;
</script>
```

## Asset Properties

Each asset in the inventory supports these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fqdn` | string | yes | Domain name |
| `cdn` | boolean | yes | CDN detected |
| `waf` | boolean | yes | WAF detected |
| `origin_hidden` | boolean | no | Origin IP not directly accessible (default: true if cdn) |
| `rate_limiting` | boolean | no | Rate-limit headers observed |
| `vendor` | string | no | Protection vendor (cloudflare, aws, akamai, etc.) |
| `scrubbing` | string | no | Scrubbing center vendor (radware, arbor, etc.) |
| `has_tunnel` | boolean | no | Behind tunnel/ZTNA (Cloudflare Tunnel, etc.) |

## Advanced Options

```python
result = calculate_opi(
    assets=assets,
    cdn_quality="enterprise",
    scrubbing_vendor="radware",      # Dedicated scrubbing center
    pipeline_gbps=10.0,              # Upstream link capacity
    isp_tier="standard",             # ISP DDoS protection tier
)
```

### CDN Quality Tiers

| Tier | Examples | L7 Base Score |
|------|----------|---------------|
| `enterprise` | Cloudflare Enterprise, AWS Shield Advanced | 80 |
| `standard` | Cloudflare Pro, CloudFront | 55 |
| `basic` | Cloudflare Free | 40 |
| `none` | No CDN | 10 |

### ISP Protection Tiers

| Tier | Typical Capacity | L3/L4 Base |
|------|-----------------|------------|
| `enterprise` | SLA-backed, dedicated | 70 |
| `premium` | 10-50 Gbps scrubbing | 55 |
| `standard` | ~5 Gbps included | 40 |
| `basic` | Best-effort, <2 Gbps | 25 |
| `none` | No ISP protection | 0 |

### Vendor Automation Tiers

The calculator scores vendor automation capability - how programmable the protection stack is:

| Tier | Score | Vendors |
|------|-------|---------|
| Full API | 100 | Cloudflare, AWS, Azure, GCP |
| Management API | 75-80 | Radware, Netscout, Neustar |
| Guided REST | 60 | Fastly, Imperva, Gcore, Sucuri |
| CLI/Manual | 20 | Akamai Prolexic, F5 |

### Vendor Bot Detection Depth (v1.2.0)

Evasion Resistance now uses empirical bot detection depth scores derived from JavaScript reverse engineering of vendor challenge pages. Higher scores mean the vendor fingerprints visitors more aggressively, making automated attacks harder to execute.

| Depth | Vendors |
|-------|---------|
| 95 | F5 / Shape |
| 85-90 | Akamai, PerimeterX / HUMAN, Vercara / Neustar |
| 75-80 | Imperva / Incapsula, Sucuri, DDoS-Guard, Kasada |
| 65-70 | Radware, DataDome |
| 50-60 | Cloudflare, AWS / CloudFront, Fortinet, Check Point, GCP / Cloud Armor |
| 35-45 | Fastly, Signal Sciences, Gcore, Lumen, Citrix / NetScaler |
| 20 | Azure / Microsoft |

When asset data includes `cdn_provider`, `waf_provider`, or `appliance_vendor` fields, the calculator automatically looks up the vendor's bot detection depth and uses it for evasion scoring instead of the previous static tiers.

## Measured Mode

When you have actual attack test results, pass them for precise scoring instead of estimation:

```python
result = calculate_opi(
    assets=assets,
    cdn_quality="enterprise",
    attack_results={
        "http_flood": {"availability": 99.5, "latency_factor": 85, "error_rate": 0.005},
        "slowloris": {"availability": 100, "latency_factor": 95, "error_rate": 0.0},
        "rapid_reset": 90,   # Protocol attacks: direct score 0-100
    },
    operational_measured={
        "availability": 98.5,
        "latency_factor": 82,
        "fp_rate": 0.01,
        "recovery_seconds": 12,
    },
    evasion_measured={
        "ja3_detected": True,
        "ua_detected": True,
        "slow_detected": False,
        "ip_rotation_handled": True,
        "header_detected": False,
    },
)
```

## Normalization

Compare scores across different attack intensities:

```python
from opi_calculator.calculator import normalized_opi

# Same OPI 70, but different attack scale
lab = normalized_opi(70, fleet_rps=5000, fleet_count=1)       # ~91.4
prod = normalized_opi(70, fleet_rps=500000, fleet_count=100)  # ~117.6
```

## Tests

```bash
cd python
pip install pytest
pytest tests/ -v
```

## Specification

Full OPI specification: [ddactic.net/opi](https://ddactic.net/opi)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Issues and PRs welcome.

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

**Open Protection Index** - Measure what matters.

*Created by [DDactic](https://ddactic.net)*

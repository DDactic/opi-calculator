# Changelog

All notable changes to the Open Protection Index specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Protocol detection test suite
- Conformance test framework
- Reference implementation improvements
- Dashboard weight alignment (6-axis to match spec)

---

## [1.3.0] - 2026-03-30

### Added

#### On-Premises Vendor Classification (Section 4.5.6)
- Three-way vendor classification: `security_waf`, `ddos_appliance`, `cloud_waf`
- Security WAFs (Check Point, FortiGate, Palo Alto, F5 ASM) get 40% WAF credit and 15 pt L3/L4 bonus - DPI shares CPU with IPS/AV/SSL, collapses under DDoS
- DDoS appliances (Radware DefensePro, Netscout Arbor, A10 Thunder, FortiDDoS) get 70% WAF credit and 45 pt L3/L4 bonus - hardware-accelerated
- Cloud WAFs keep 100% credit
- L7 resilience cap at 25 for security_waf-only setups (no CDN, no DDoS appliance)
- Test plan vector priority boosting by vendor class
- Hardening recommendation differentiation: security_waf = "add cloud DDoS upstream", ddos_appliance = "tune thresholds"

### Changed
- WAF Deployment factor (Factor 2) now scores on-prem appliances differently based on vendor class instead of flat 70% for all on-prem
- L3/L4 bonus scoring uses vendor_class instead of binary has_onprem_ddos/has_onprem_lb

---

## [1.1.0] - 2026-03-21

### Added

#### Assessment Tiers (Section 3.4)
- OPI Passive: infrastructure coverage from DNS/HTTP headers only
- OPI Estimated: passive + L7 recon + client-provided data
- OPI Validated: post active test with measured resilience data
- Tier disclosure requirements in conformance section (8.3)

#### L7 Attack Surface Assessment (Section 4.2.5)
- Passive detection of DDoS-relevant application-layer attack vectors
- GraphQL introspection penalty (-12): complexity attacks bypass cache
- GraphQL endpoints penalty (-4 to -8): uncacheable query surface
- WordPress XMLRPC penalty (-6): pingback amplification vector
- Rate limiting absence penalty (-8): unlimited auth request volume
- API surface size penalty (-3 to -6): cache-bypass vectors
- Penalties only apply at Estimated/Validated tiers (not Passive)

#### Client-Provided Data Integration (Section 4.2.6)
- WAF rule count, rate limiting config, auto-scaling policy
- Bot management, GraphQL complexity limits, XMLRPC confirmation
- Client data can neutralize penalties or add score bonuses
- Must be labeled and verified during Validated tier

#### Score Example 4
- New example: "Well-Protected but Exposed API Surface" showing L7 penalties

### Changed
- Specification version bumped to 1.1.0
- Conformance section expanded with tier disclosure requirements (8.3)

---

## [1.0.0] - 2025-12-16

### Added

#### Core Specification
- Initial OPI specification with 6 scoring components
- Defense Coverage Score (20% weight)
- L7 Attack Resilience Score (25% weight)
- L3/L4 Attack Resilience Score (15% weight)
- Protocol Resilience Score (15% weight)
- Operational Resilience Score (15% weight)
- Evasion Resistance Score (10% weight)

#### Grading System
- A-F letter grades based on score ranges
- Score normalization by attack intensity
- Attack intensity levels (Lab, Small, Medium, Large)

#### Attack Vectors
- HTTP/1.1 flood testing (GET, POST, HEAD)
- HTTP/2 specific attacks (Rapid Reset CVE-2023-44487, CONTINUATION Flood CVE-2024-27316)
- HTTP/3/QUIC attacks (Initial Flood, CID Exhaustion)
- Slowloris family (Slowloris, Slow POST, Slow Read)
- Cache bypass attacks
- L3/L4 attacks (SYN, UDP, Amplification)

#### Evasion Techniques
- JA3/JA4 fingerprint rotation detection
- User-Agent rotation detection
- Slow rate attack detection
- IP rotation handling
- Header randomization detection

#### Operational Metrics
- Availability measurement
- Latency degradation scoring
- False positive rate calculation
- Recovery time measurement

#### Documentation
- Full specification document (SPEC.md)
- Contributing guidelines (CONTRIBUTING.md)
- README with quick start guide
- Apache 2.0 license

### Security
- Added authorization requirements for testing
- Included attack intensity safeguards
- Data handling recommendations

---

## Version History

| Version | Date | Status |
|---------|------|--------|
| 1.0.0 | 2025-12-16 | Draft for Public Review |

---

## Versioning Policy

OPI follows semantic versioning:

- **MAJOR** (X.0.0): Breaking changes to scoring methodology
- **MINOR** (0.X.0): New features, attack vectors, backward compatible
- **PATCH** (0.0.X): Bug fixes, clarifications, no scoring changes

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose changes.






















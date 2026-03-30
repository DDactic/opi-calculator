# Open Protection Index (OPI) - Specification

**Version:** 1.3.0
**Status:** Draft for Public Review
**Last Updated:** 2026-03-30
**Maintained By:** DDactic (Founding Organization)  
**License:** Apache 2.0

---

## Abstract

The **Open Protection Index (OPI)** is an open, vendor-neutral standard for measuring an organization's resilience against Distributed Denial of Service (DDoS) attacks. Unlike simple uptime metrics, OPI provides a comprehensive, multi-dimensional score (0-100) that evaluates defense architecture, attack-specific resilience, protocol vulnerabilities, operational performance, and evasion resistance.

This specification defines the scoring methodology, test procedures, and reporting format for OPI assessments.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Score Structure](#3-score-structure)
4. [Component Specifications](#4-component-specifications)
5. [Test Methodology](#5-test-methodology)
6. [Normalization](#6-normalization)
7. [Reporting Format](#7-reporting-format)
8. [Conformance](#8-conformance)
9. [Security Considerations](#9-security-considerations)
10. [References](#10-references)
11. [Appendices](#11-appendices)

---

## 1. Introduction

### 1.1 Purpose

The Open Protection Index (OPI) provides a standardized methodology for:

1. **Pre-engagement assessment** - Evaluate protection posture before testing
2. **Post-engagement scoring** - Quantify resilience after attack simulation
3. **Comparative analysis** - Compare protection across vendors/configurations
4. **Continuous monitoring** - Track protection improvements over time

### 1.2 Scope

This specification covers:
- Layer 7 (Application) DDoS protection assessment
- Layer 3/4 (Network/Transport) DDoS protection assessment
- Protocol-specific vulnerability testing (HTTP/2, HTTP/3/QUIC)
- Defense detection and coverage analysis
- Evasion technique resistance

### 1.3 Design Principles

| Principle | Description |
|-----------|-------------|
| **Open** | Freely available, no licensing fees |
| **Vendor-Neutral** | Not tied to any specific vendor or product |
| **Reproducible** | Same inputs produce same scores |
| **Transparent** | All formulas and weights are public |
| **Extensible** | New attack vectors can be added |

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **OPI Score** | The final protection index (0-100) |
| **Component Score** | Individual score for each of the 6 components |
| **Attack Intensity** | Measure of attack volume (RPS, bot count) |
| **Normalized OPI** | OPI adjusted for attack intensity |
| **Validator** | External service verifying availability |
| **False Positive** | Legitimate request incorrectly blocked |

### 2.1 Conformance Keywords

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

---

## 3. Score Structure

### 3.1 Overall Score

The OPI score is calculated as a weighted sum of six components:

```
OPI = (
    Defense_Coverage      × 0.20  +
    L7_Attack_Resilience  × 0.25  +
    L3L4_Attack_Resilience × 0.15  +
    Protocol_Resilience   × 0.15  +
    Operational_Resilience × 0.15  +
    Evasion_Resistance    × 0.10
)
```

### 3.2 Grade Scale

| Score Range | Grade | Classification | Description |
|-------------|-------|----------------|-------------|
| 90-100 | A | Excellent | Enterprise-grade protection |
| 80-89 | B | Good | Solid defenses with minor gaps |
| 70-79 | C | Adequate | Basic protection, significant risks |
| 60-69 | D | Poor | Major vulnerabilities present |
| 0-59 | F | Critical | Minimal to no protection |

### 3.3 Component Weights Rationale

| Component | Weight | Rationale |
|-----------|--------|-----------|
| L7 Attack Resilience | 25% | L7 attacks represent 71% of all DDoS |
| Defense Coverage | 20% | Architecture determines baseline protection |
| L3/L4 Resilience | 15% | Important but often CDN-mitigated |
| Protocol Resilience | 15% | Modern protocol vulnerabilities are critical |
| Operational Resilience | 15% | Real-world availability matters |
| Evasion Resistance | 10% | Advanced attacks require sophisticated detection |

### 3.4 Assessment Tiers

OPI scores vary in accuracy depending on the data available. Implementations MUST disclose which tier applies.

| Tier | Label | Data Sources | Accuracy | Use Case |
|------|-------|-------------|----------|----------|
| Passive | OPI Passive | DNS, HTTP headers, certificate transparency, WHOIS | Low-Medium | Free scans, initial triage |
| Estimated | OPI Estimated | Passive + L7 recon (crawl, probe, API discovery) + client-provided data | Medium-High | Pre-engagement assessment |
| Validated | OPI Validated | Estimated + active attack simulation results | High | Post-engagement scoring |

#### 3.4.1 Passive Tier

Scores infrastructure coverage only (CDN/WAF presence, origin exposure). Components that require active testing (L7 resilience under load, protocol resilience, operational metrics, evasion resistance) use architecture-inferred estimates. Reports MUST include the note: "Pre-test estimate based on passive reconnaissance."

**Limitations:**
- Cannot measure actual resilience under attack pressure
- Cannot validate WAF rule effectiveness or rate limit thresholds
- Cannot detect on-demand scrubbing centers (only always-on)
- CDN/WAF detection is header-based (may miss proxy-mode configurations)
- Caching effectiveness unknown (static vs dynamic content ratio)
- Auto-scaling capability unknown without client input

#### 3.4.2 Estimated Tier

Supplements passive data with L7 application reconnaissance and client-provided configuration. The L7 Attack Surface Assessment (Section 4.2.5) applies penalties for detected DDoS-relevant attack vectors that bypass CDN/WAF protection.

**Additional data sources:**
- GraphQL endpoint and introspection detection
- API surface size and cache-bypass potential
- Rate limiting presence/absence per endpoint
- Authentication flow exposure
- WordPress XMLRPC and amplification vectors
- Client-provided: auto-scaling config, WAF rule count, scrubbing tier

#### 3.4.3 Validated Tier

Active testing produces measured values for all six components. This tier replaces estimates with observed data: actual availability under attack, measured latency degradation, real error rates, and observed recovery times. Validated OPI is the authoritative score.

---

## 4. Component Specifications

### 4.1 Defense Coverage Score (20%)

#### 4.1.1 Purpose

Measures deployed defenses BEFORE any attack testing. This component evaluates architectural protection.

#### 4.1.2 Sub-components

| Factor | Weight | Scoring |
|--------|--------|---------|
| CDN Deployment | 25% | 100: All assets behind CDN, 0: No CDN |
| WAF Deployment | 25% | 100: WAF on all endpoints, 0: No WAF |
| Origin Protection | 20% | 100: Origin hidden/firewalled, 0: Origin exposed |
| Rate Limiting | 15% | 100: Per-endpoint limits, 0: No limits |
| Scrubbing Center | 15% | 100: Always-on scrubbing, 50: On-demand, 0: None |

#### 4.1.3 Formula

```python
def defense_coverage_score(target):
    cdn = 100 if target.cdn_detected else 0
    waf = 100 if target.waf_detected else (50 if target.rate_limiting else 0)
    origin = 100 if not target.origin_exposed else 0
    rate_limit = measure_rate_limiting(target)
    scrubbing = 100 if target.scrubbing_center else (50 if target.on_demand else 0)
    
    return (cdn * 0.25 + waf * 0.25 + origin * 0.20 + 
            rate_limit * 0.15 + scrubbing * 0.15)
```

#### 4.1.4 Detection Methods

Implementations MUST support detection of:

- **CDN**: CNAME patterns, server headers, IP ranges
- **WAF**: Challenge pages, block pages, response headers
- **Origin Exposure**: Historical DNS, certificate transparency, direct IP testing

---

### 4.2 L7 Attack Resilience Score (25%)

#### 4.2.1 Purpose

Measures resilience against application-layer attacks, the most common attack type.

#### 4.2.2 Attack Categories

| Category | Attacks | Weight | Test Duration |
|----------|---------|--------|---------------|
| HTTP Floods | GET, POST, HEAD | 30% | 60s each |
| Slowloris Family | Slowloris, Slow POST, Slow Read | 20% | 120s |
| Resource Exhaustion | LFD, Upload, Search abuse | 20% | 60s |
| Cache Bypass | Random params, POST bypass | 15% | 60s |
| API Abuse | Endpoint flood, GraphQL | 15% | 60s |

#### 4.2.3 Per-Attack Scoring Formula

```python
def attack_resilience_score(attack_results):
    """
    Calculate resilience for a single attack type.
    
    Components:
    - Availability: % of successful requests during attack (50%)
    - Latency: Inverse of latency degradation (30%)
    - Error Rate: Inverse of error rate (20%)
    """
    availability = (attack_results.successful / attack_results.total) * 100
    latency_factor = min(100, (baseline_latency / attack_latency) * 100)
    error_factor = (1 - attack_results.error_rate) * 100
    
    return (availability * 0.50 + latency_factor * 0.30 + error_factor * 0.20)
```

#### 4.2.4 HTTP Version Testing Matrix

| Attack | HTTP/1.1 | HTTP/2 | HTTP/3 |
|--------|----------|--------|--------|
| GET Flood | REQUIRED | REQUIRED | OPTIONAL |
| POST Flood | REQUIRED | REQUIRED | OPTIONAL |
| HEAD Flood | OPTIONAL | OPTIONAL | - |
| Cache Bust | REQUIRED | REQUIRED | REQUIRED |

#### 4.2.5 L7 Attack Surface Assessment (Estimated and Validated Tiers)

When active testing is not available, the L7 score SHOULD be adjusted based on passively detectable attack surface that directly impacts DDoS resilience. These penalties reflect cache-bypass vectors, amplification potential, and resource exhaustion paths that CDN/WAF cannot mitigate without explicit configuration.

| Finding | Penalty | DDoS Rationale | Detection Method |
|---------|---------|----------------|------------------|
| GraphQL introspection enabled | -12 | Complexity attacks bypass cache, expensive queries exhaust origin DB/CPU | Probe /graphql with introspection query |
| GraphQL endpoints (>5 detected) | -8 | Large uncacheable query surface | HTTP crawl + JS endpoint extraction |
| GraphQL endpoints (1-5 detected) | -4 | Some uncacheable surface | HTTP crawl + JS endpoint extraction |
| WordPress XMLRPC enabled | -6 | Pingback amplification vector (reflected DDoS) | Probe /xmlrpc.php |
| No rate limiting + exposed login endpoints (>3) | -8 | Unlimited authentication request volume | Rate limit header absence + login form detection |
| Large API surface (>20 uncacheable endpoints) | -6 | Many cache-bypass vectors, each a potential flood target | JS crawl + API path enumeration |
| API surface (5-20 uncacheable endpoints) | -3 | Some cache-bypass vectors | JS crawl + API path enumeration |

**Application rules:**

1. Penalties are cumulative but the L7 score floor is 0
2. Penalties apply only when L7 reconnaissance data is available (Estimated/Validated tiers)
3. At the Passive tier, no penalties apply (data not collected)
4. Active testing results (Validated tier) supersede penalty-based estimates
5. Implementations MUST document which penalties were applied

```python
def l7_attack_surface_penalty(l7_findings):
    """
    Calculate L7 DDoS-relevant penalty from passive reconnaissance.
    Applied to L7 Attack Resilience sub-score before weighting.
    """
    penalty = 0
    counts = Counter(f.finding_type for f in l7_findings)

    # GraphQL complexity attacks bypass CDN cache
    if counts.get('graphql_introspection', 0) > 0:
        penalty += 12
    elif counts.get('graphql_endpoint', 0) > 5:
        penalty += 8
    elif counts.get('graphql_endpoint', 0) > 0:
        penalty += 4

    # WordPress pingback amplification
    if counts.get('wp_xmlrpc', 0) > 0:
        penalty += 6

    # No rate limiting on auth endpoints = unlimited volume
    has_rate_limit = counts.get('rate_limit_config', 0) > 0
    login_count = counts.get('login_endpoint', 0) + counts.get('login_detected', 0)
    if not has_rate_limit and login_count > 3:
        penalty += 8

    # Large uncacheable API surface
    api_count = counts.get('api_endpoint_discovered', 0) + counts.get('graphql_endpoint', 0)
    if api_count > 20:
        penalty += 6
    elif api_count > 5:
        penalty += 3

    return penalty
```

#### 4.2.6 Client-Provided Data Integration

When the target organization provides configuration data, implementations MAY adjust the L7 score:

| Client Data | Impact | Direction |
|-------------|--------|-----------|
| WAF rule count and custom rules | +5 to +15 | Increases score (validated protection) |
| Rate limiting configuration (per-endpoint) | +5 to +10 | Increases score |
| Auto-scaling policy (fully managed vs self-managed) | -10 to +10 | Adjusts based on scaling capability |
| Bot management solution deployed | +5 to +10 | Increases score |
| GraphQL complexity limits configured | Removes -12 penalty | Neutralizes finding |
| XMLRPC disabled (client confirms) | Removes -6 penalty | Neutralizes finding |

Client-provided data MUST be clearly labeled in reports and SHOULD be verified during Validated tier testing.

---

### 4.3 L3/L4 Attack Resilience Score (15%)

#### 4.3.1 Purpose

Measures resilience against network and transport layer attacks.

#### 4.3.2 Special Consideration: Hidden Origins

If the origin IP is properly hidden behind a CDN (not directly accessible), implementations MUST award an automatic score of **85 points**. This reflects architectural protection.

Full 100 points requires:
- Origin hidden behind CDN, AND
- Scrubbing center in front of origin, AND
- ISP-level DDoS protection

#### 4.3.3 Attack Categories (When Origin Accessible)

| Category | Attacks | Weight |
|----------|---------|--------|
| TCP Floods | SYN, SYN-ACK, ACK, RST | 40% |
| UDP Floods | UDP, Fragmentation | 30% |
| Amplification | DNS, NTP | 20% |
| Protocol Abuse | GRE, ESP, IP-in-IP | 10% |

---

### 4.4 Protocol Resilience Score (15%)

#### 4.4.1 Purpose

Modern protocols (HTTP/2, HTTP/3/QUIC) have unique vulnerabilities not present in HTTP/1.1.

#### 4.4.2 HTTP/2 Specific Attacks

| Attack | CVE | Description | Weight |
|--------|-----|-------------|--------|
| Rapid Reset | CVE-2023-44487 | Stream reset flood | 35% |
| CONTINUATION Flood | CVE-2024-27316 | Memory exhaustion | 25% |
| PING Flood | - | Control frame abuse | 15% |
| SETTINGS Flood | - | Connection resource exhaustion | 15% |
| Empty Frame | - | Parser exhaustion | 10% |

#### 4.4.3 HTTP/3/QUIC Specific Attacks

| Attack | Description | Weight |
|--------|-------------|--------|
| Initial Flood | Fake handshake flood | 25% |
| CID Exhaustion | Connection ID cycling | 25% |
| 0-RTT Replay | Replay attack amplification | 20% |
| Version Negotiation | Negotiation abuse | 15% |
| ACK Manipulation | Send buffer inflation | 15% |

#### 4.4.4 Scoring Logic

If a protocol is not supported by the target, attacks specific to that protocol are marked as N/A and excluded from scoring (not penalized).

---

### 4.5 Operational Resilience Score (15%)

#### 4.5.1 Purpose

Measures real-world availability during attacks using external validators.

#### 4.5.2 Required Validators

| Validator Type | Weight | Purpose |
|----------------|--------|---------|
| ISP/Residential Probes | 35% | Detect false positives from residential IPs |
| Datacenter Probes | 25% | Global availability from cloud IPs |
| Real Browser | 20% | User experience validation |
| Local Baseline | 10% | Reference measurement |
| Third-party Monitor | 10% | Independent verification |

#### 4.5.3 Metrics

| Metric | Weight | Description |
|--------|--------|-------------|
| Availability | 35% | % successful requests during attack |
| Latency | 25% | Latency degradation ratio |
| False Positive Rate | 20% | % legitimate requests blocked |
| Recovery Time | 20% | Time to return to baseline |

#### 4.5.4 Formula

```python
def operational_resilience_score(baseline, attack, recovery):
    availability = (attack.successful / attack.total) * 100
    latency_score = min(100, (baseline.latency / attack.latency) * 100)
    fp_score = (1 - (attack.blocked_legitimate / attack.total_legitimate)) * 100
    recovery_score = max(0, 100 - (recovery.seconds / 60 * 100))

    return (availability * 0.35 + latency_score * 0.25 +
            fp_score * 0.20 + recovery_score * 0.20)
```

#### 4.5.5 Scaling Architecture Taxonomy

Backend scaling architecture directly affects DDoS resilience. Scaling speed matters more than raw capacity because DDoS attacks ramp up in seconds, not minutes. A system that scales in 5 seconds absorbs a flood; one that scales in 5 minutes goes down first.

**Scaling Types and OPI Impact:**

| Type | Speed | Capacity | Detection Method | OPI Adjustment |
|------|-------|----------|-----------------|----------------|
| Cloud CDN auto-scale | Instant (~0s) | Near-infinite | Passive (CNAME patterns) | Already captured in CDN score |
| Serverless (Lambda/Cloud Run/Vercel) | Instant | Concurrency-limited | Passive (CNAME patterns) | +5 operational resilience |
| HPA with pre-loaded images | Fast (5-30s) | Cluster-limited | Semi-passive (x-kubernetes headers) | +8 operational resilience |
| Horizontal Pod Autoscaling (HPA) | Fast (10-60s) | Cluster-limited | Semi-passive (x-kubernetes headers) | +5 operational resilience |
| Kubernetes KEDA (event-driven) | Fast (15-45s) | Cluster-limited | Cannot detect passively | +5 (client questionnaire) |
| VM pools (pre-warmed) | Medium (30-60s) | Pool-limited | Cannot detect passively | +3 (client questionnaire) |
| VM Auto-Scaling Groups (ASG/VMSS) | Slow (2-5 min) | Region-limited | Cannot detect passively | +2 (client questionnaire) |
| Vertical scaling (bigger VM) | Very slow (reboot) | Single-VM ceiling | Cannot detect passively | 0 (no resilience benefit) |
| Manual scaling | Human-speed (min-hours) | Whatever ops provisions | Cannot detect passively | 0 |

**Key principles:**

1. Most scaling types cannot be detected passively. The Infrastructure Questionnaire (Section 4.2.6) is the primary data source.
2. Scaling speed determines resilience value. Instant and fast scaling (under 30s) absorb attack surges before users notice. Slow scaling (minutes) means the service degrades or drops before new capacity arrives.
3. Combined architectures compound resilience. CDN auto-scale at the edge plus HPA at the backend provides layered absorption. On-prem load balancer with a pre-warmed VM pool provides medium resilience.
4. Capacity ceilings matter at Validated tier. Serverless has concurrency limits, HPA has cluster resource limits, and ASG has region quotas. Active testing reveals whether scaling keeps up under sustained load.

**Detection heuristics (Passive and Estimated tiers):**

- Serverless: CNAME to `*.cloudfunctions.net`, `*.lambda-url.*`, `*.vercel.app`, `*.workers.dev`
- Kubernetes: `x-kubernetes-*` response headers, `server: envoy` with specific patterns
- CDN auto-scale: Already captured in Defense Coverage (Section 4.1)
- All other types: Require client questionnaire input

**Formula integration:**

The scaling adjustment applies to the Operational Resilience component (Section 4.5). At the Estimated tier, the adjustment is added as a bonus. At the Validated tier, measured scaling behavior under load supersedes the estimate.

```python
def scaling_architecture_bonus(scaling_type):
    """
    Returns operational resilience bonus based on declared or detected
    scaling architecture. Applied at Estimated tier only.
    """
    SCALING_BONUS = {
        'serverless':           5,
        'hpa_preloaded':        8,
        'hpa':                  5,
        'keda':                 5,
        'vm_pool_prewarmed':    3,
        'asg':                  2,
        'vertical':             0,
        'manual':               0,
        'none':                 0,
    }
    return SCALING_BONUS.get(scaling_type, 0)
```

---

### 4.5.6 On-Premises Vendor Classification

OPI distinguishes three classes of protection appliances, each with different DDoS behavior and scoring:

| Vendor Class | Examples | DDoS Behavior | WAF Credit | L3/L4 Bonus |
|---|---|---|---|---|
| `security_waf` | Check Point Quantum, Fortinet FortiGate, Palo Alto PA-Series, F5 BIG-IP ASM, SonicWall, Sophos XG | Deep packet inspection shares CPU with IPS/AV/SSL. Collapses at 2-5 Gbps under sustained DDoS | 40% | 15 |
| `ddos_appliance` | Radware DefensePro, Netscout Arbor Edge/TMS, A10 Thunder TPS, Fortinet FortiDDoS | Hardware-accelerated packet processing. Purpose-built for volumetric attacks (40-400 Gbps) | 70% | 45 |
| `cloud_waf` | Cloudflare, Akamai, Imperva Cloud WAF, AWS WAF + Shield | Globally distributed PoPs with elastic capacity. Handles Tbps-scale attacks | 100% | N/A |

Additional non-DDoS classes (scored separately):
- `load_balancer`: HAProxy, Kemp, F5 LTM, Radware Alteon - no DDoS mitigation, 20 pt L3/L4 bonus for load distribution only
- `bot_management`: DataDome, PerimeterX/HUMAN - bot-specific, not volumetric DDoS

#### Scoring Rationale

**Factor 2 (WAF Deployment, 25%):** `security_waf` receives 40% credit because it provides L7 filtering under normal conditions but fails under DDoS load when the DPI engine saturates the shared CPU. `ddos_appliance` receives 70% because it is purpose-built with hardware acceleration but is limited by upstream pipe capacity and single-site deployment. `cloud_waf` receives 100% for elastic, globally distributed mitigation.

**L3/L4 Bonus:** `security_waf` receives 15 points (firewall DoS profile exists but shares CPU with IPS/AV). `ddos_appliance` receives 45 points (inline hardware-accelerated scrubbing).

**L7 Resilience Cap:** If only a `security_waf` is present (no CDN, no DDoS appliance), L7 resilience base score is capped at 25 due to expected CPU exhaustion under sustained L7 flood. Security WAFs are designed for deep inspection of individual packets, not for absorbing volumetric traffic.

#### Test Plan Implications

- **Security WAFs:** L7 HTTP floods and slow attacks are boosted to "critical" priority (overwhelm DPI engine and exhaust connection table shared with IPS/AV)
- **DDoS Appliances:** Pipe saturation and protocol-level attacks are prioritized (bypass hardware mitigation by exceeding upstream capacity)
- **Cloud WAFs:** Distributed L7 with fingerprint rotation and rate limit evasion are prioritized

#### Hardening Recommendations

- **Security WAF only:** Primary recommendation is "Add cloud DDoS layer upstream" - not "tune WAF rules"
- **DDoS Appliance:** "Tune behavioral thresholds", "Add cloud scrubbing for volumetric above appliance capacity"

---

### 4.6 Evasion Resistance Score (10%)

#### 4.6.1 Purpose

Measures effectiveness against sophisticated attacks that attempt to bypass detection.

#### 4.6.2 Evasion Techniques

| Technique | Description | Weight |
|-----------|-------------|--------|
| JA3/JA4 Randomization | TLS fingerprint rotation | 40% |
| User-Agent Rotation | Header diversity | 20% |
| Slow Rate Attack | Below threshold attacks | 20% |
| IP Rotation | Multi-source attacks | 10% |
| Header Randomization | Random header combinations | 10% |

#### 4.6.3 Scoring

```python
def evasion_resistance_score(results):
    ja3 = 100 if results.ja3_detected else 0
    ua = 100 if results.ua_detected else 50
    slow = 100 if results.slow_detected else 30
    ip = 100 if results.ip_rotation_handled else 50
    header = 100 if results.header_detected else 50
    
    return (ja3 * 0.40 + ua * 0.20 + slow * 0.20 + ip * 0.10 + header * 0.10)
```

---

## 5. Test Methodology

### 5.1 Test Phases

#### Phase 1: Pre-Test (Reconnaissance)

```
1. Enumerate all domains/subdomains
2. Detect CDN/WAF/Scrubbing centers
3. Identify origin IPs (if exposed)
4. Map API endpoints
5. Detect protocol support (HTTP/1.1, HTTP/2, HTTP/3)
```

#### Phase 2: Baseline Measurement

```
1. Measure latency from all validators
2. Verify 100% availability
3. Document normal response patterns
4. Establish rate limiting thresholds
```

#### Phase 3: Attack Testing

```
1. L7 Attack Tests (per attack category)
2. Protocol-specific tests (if protocols supported)
3. L3/L4 tests (if origin accessible)
4. Evasion technique tests
```

#### Phase 4: Recovery Measurement

```
1. Stop all attacks
2. Measure time to baseline latency
3. Measure time to 100% availability
4. Check for persistent blocks (false positives)
```

### 5.2 Test Duration Requirements

| Test Type | Minimum Duration | Recommended |
|-----------|------------------|-------------|
| Per-attack test | 30 seconds | 60 seconds |
| Slowloris family | 60 seconds | 120 seconds |
| Recovery measurement | Until baseline | Max 300 seconds |

---

## 6. Normalization

### 6.1 Purpose

Allow comparison across different attack scales. A target surviving 100k RPS with OPI 70 is more resilient than one surviving 1k RPS with OPI 70.

### 6.2 Attack Intensity Levels

| Level | Name | Bot Count | RPS Range |
|-------|------|-----------|-----------|
| 1 | Lab | 1 | 0-5,000 |
| 2 | Small | 5-10 | 5,000-50,000 |
| 3 | Medium | 50-100 | 50,000-500,000 |
| 4 | Large | 500+ | 500,000+ |

### 6.3 Normalization Formula

```python
import math

def normalized_opi(raw_opi, load fleet_rps, load fleet_count):
    """
    Normalize OPI by attack intensity.
    Higher intensity with same OPI = better resilience.
    """
    intensity_factor = math.log10(1 + load fleet_rps)
    scale_factor = math.log10(1 + load fleet_count)
    
    return raw_opi * (1 + (intensity_factor * 0.1) + (scale_factor * 0.05))
```

---

## 7. Reporting Format

### 7.1 Executive Summary (REQUIRED)

```
Target: example.com
Test Date: YYYY-MM-DD
Attack Duration: X hours
Attack Intensity: Level N (description)

OPI SCORE: XX/100 (Grade: X)

Component Breakdown:
  Defense Coverage:      XX/100
  L7 Attack Resilience:  XX/100
  L3/L4 Resilience:      XX/100
  Protocol Resilience:   XX/100
  Operational:           XX/100
  Evasion Resistance:    XX/100

TOP FINDINGS:
  1. [SEVERITY] Finding description
  2. [SEVERITY] Finding description
  ...
```

### 7.2 Finding Severity Levels

| Level | Description |
|-------|-------------|
| CRITICAL | Immediate exploitation possible, service outage likely |
| HIGH | Significant vulnerability, moderate attack can exploit |
| MEDIUM | Vulnerability present, requires sustained attack |
| LOW | Minor issue, minimal impact |

---

## 8. Conformance

### 8.1 Implementation Requirements

An OPI-conformant implementation MUST:

1. Implement all six component calculations
2. Use the specified weights
3. Support at least HTTP/1.1 and HTTP/2 testing
4. Include at least two external validator types
5. Generate reports in the specified format
6. Disclose any deviations in the report

### 8.2 Certification Levels

| Level | Requirements |
|-------|--------------|
| OPI Basic | Components 1-5 implemented |
| OPI Full | All 6 components implemented |
| OPI Extended | Full + custom extensions documented |

### 8.3 Tier Disclosure Requirements

Implementations MUST:

1. Clearly label the assessment tier (Passive, Estimated, or Validated)
2. List which L7 Attack Surface penalties (Section 4.2.5) were applied, if any
3. Disclose any client-provided data used (Section 4.2.6)
4. Note data sources that were unavailable (e.g., "No active testing performed")
5. At the Passive tier, include: "Pre-test estimate based on passive reconnaissance. Full OPI requires active testing."

---

## 9. Security Considerations

### 9.1 Authorization

OPI assessments MUST only be conducted with explicit written authorization from the target owner.

### 9.2 Attack Intensity

Implementations SHOULD provide safeguards to prevent excessive attack intensity that could cause unintended damage.

### 9.3 Data Handling

Assessment results MAY contain sensitive information about target vulnerabilities. Results SHOULD be transmitted and stored securely.

---

## 10. References

1. OWASP Testing Guide v4.2
2. NIST SP 800-115 (Technical Guide to Information Security Testing)
3. RFC 2119 (Key words for use in RFCs)
4. CVE-2023-44487 (HTTP/2 Rapid Reset)
5. CVE-2024-27316 (HTTP/2 CONTINUATION Flood)

---

## 11. Appendices

### Appendix A: Attack Vector Reference

#### Active Vectors (RECOMMENDED for Testing)

| # | Attack | Layer | Tool Example |
|---|--------|-------|--------------|
| 1 | HTTP GET Flood | L7 | siege, wrk, custom |
| 2 | HTTP POST Flood | L7 | custom |
| 3 | Slowloris | L7 | slowloris |
| 4 | Cache Bypass | L7 | custom (random params) |
| 5 | HTTP/2 Rapid Reset | L7 | h2load, custom |
| 6 | SYN Flood | L4 | hping3 |
| 7 | UDP Flood | L4 | hping3 |

#### Obsolete Vectors (DO NOT USE)

| Attack | Reason |
|--------|--------|
| Ping of Death | Patched since 1997 |
| Smurf Attack | Broadcast disabled |
| Teardrop | Patched since 1998 |
| Land Attack | Patched since 1997 |

### Appendix B: Score Examples

#### Example 1: Unprotected Origin (OPI: 15)

```
Defense Coverage:     0 (no CDN, no WAF)
L7 Resilience:       10 (crashes at 500 RPS)
L3/L4 Resilience:     0 (origin exposed, no protection)
Protocol Resilience: 30 (basic Apache, unpatched)
Operational:         20 (outage in 30 seconds)
Evasion Resistance:   0 (no detection)

OPI: 15/100 (Grade: F)
```

#### Example 2: CDN-Only (OPI: 55)

```
Defense Coverage:    50 (CDN but no WAF)
L7 Resilience:       60 (CDN absorbs basic floods)
L3/L4 Resilience:    70 (CDN hides origin)
Protocol Resilience: 50 (CDN handles protocols)
Operational:         60 (some latency increase)
Evasion Resistance:  30 (no behavioral detection)

OPI: 55/100 (Grade: D)
```

#### Example 3: Enterprise Stack (OPI: 85)

```
Defense Coverage:    95 (CDN + WAF + scrubbing)
L7 Resilience:       90 (rate limiting + WAF rules)
L3/L4 Resilience:    95 (origin fully hidden)
Protocol Resilience: 75 (patched, H2 limits configured)
Operational:         85 (minimal degradation)
Evasion Resistance:  70 (behavioral detection enabled)

OPI: 85/100 (Grade: B)
```

#### Example 4: Well-Protected but Exposed API Surface (Estimated Tier)

```
Defense Coverage:    90 (CDN + WAF on all assets)
L7 Resilience:       52 (base 70 from CDN+WAF, minus penalties:
                         -8 GraphQL endpoints >5 detected
                         -8 no rate limiting on login endpoints
                         -6 API surface >20 uncacheable endpoints)
                         Note: L7 base from CDN+WAF is high, but
                         passive recon reveals cache-bypass vectors
L3/L4 Resilience:    85 (origin hidden behind CDN)
Protocol Resilience: -- (not tested, passive tier)
Operational:         -- (not tested, passive tier)
Evasion Resistance:  -- (not tested, passive tier)

OPI Estimated: 72/100 (Grade: C)
Note: Pre-test estimate. Active testing may validate
      higher or lower L7 resilience.
```

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.2.0 | 2026-03-26 | Added Scaling Architecture Taxonomy (4.5.5) with detection heuristics and OPI adjustments |
| 1.1.0 | 2026-03-21 | Added Assessment Tiers (3.4), L7 Attack Surface Assessment penalties (4.2.5), Client-Provided Data Integration (4.2.6) |
| 1.0.0 | 2025-12-16 | Initial public draft |

---

## Contributing

This is an open specification. Contributions are welcome via:

- GitHub Issues: Report bugs, suggest improvements
- Pull Requests: Propose specification changes
- Mailing List: Discuss methodology changes

See CONTRIBUTING.md for guidelines.

---

**Open Protection Index (OPI)** - An open standard for DDoS resilience measurement.

*Founded by DDactic | Licensed under Apache 2.0*


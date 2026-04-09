"""
OPI Calculator - Open Protection Index scoring engine.

Implements the OPI v1.1.0 specification for measuring DDoS resilience.
See: https://github.com/ddactic/opi-calculator

Usage:
    from opi_calculator import calculate_opi

    result = calculate_opi(
        assets=[
            {"fqdn": "app.example.com", "cdn": True, "waf": True, "origin_hidden": True},
            {"fqdn": "api.example.com", "cdn": True, "waf": False, "origin_hidden": False},
            {"fqdn": "mail.example.com", "cdn": False, "waf": False, "origin_hidden": False},
        ],
        cdn_quality="standard",
    )
    print(f"OPI: {result['score']}/100 (Grade {result['grade']})")
"""

import math
from typing import Any


# OPI v1.1.0 component weights (Section 3.1)
WEIGHTS = {
    "defense_coverage": 0.20,
    "l7_attack": 0.25,
    "l3l4_attack": 0.15,
    "protocol": 0.15,
    "operational": 0.15,
    "evasion": 0.10,
}

# Grade scale (Section 3.2)
GRADE_SCALE = [
    (90, "A", "Excellent"),
    (80, "B", "Good"),
    (70, "C", "Adequate"),
    (60, "D", "Poor"),
    (0, "F", "Critical"),
]

# Vendor automation tiers for the protection_automation sub-component.
# Tier 1 (full API): vendors with complete programmatic WAF/DDoS rule management.
# Tier 2 (guided REST): vendors with partial API coverage.
# Tier 3 (CLI/manual): vendors requiring CLI or portal-only configuration.
VENDOR_AUTOMATION_TIERS = {
    "cloudflare": 100, "aws": 100, "cloudfront": 100, "amazon": 100,
    "azure": 100, "microsoft": 100, "google": 100, "gcp": 100,
    "radware": 80, "arbor": 75, "netscout": 75, "neustar": 75,
    "fastly": 60, "imperva": 60, "incapsula": 60, "gcore": 60, "sucuri": 60,
    "akamai": 20, "prolexic": 20, "f5": 20,
}

# Scrubbing center quality tiers.
# Scores reflect out-of-box mitigation effectiveness without manual tuning.
SCRUBBING_QUALITY = {
    "radware": 90,    # DPX behavioral engine, best out-of-box
    "imperva": 75,    # Strong L3/4+L7 combined
    "incapsula": 75,
    "neustar": 72,    # UltraDDoS Protect
    "akamai": 70,     # Prolexic, benefits from tuning
    "prolexic": 70,
    "netscout": 65,   # Sightline/TMS, requires threshold tuning
    "arbor": 60,      # TMS weak out-of-box
    "f5": 55,         # Silverline
}


def grade_from_score(score: int) -> dict:
    """Convert numeric OPI score to grade and classification."""
    for threshold, letter, classification in GRADE_SCALE:
        if score >= threshold:
            return {"grade": letter, "classification": classification}
    return {"grade": "F", "classification": "Critical"}


def defense_coverage_score(assets: list[dict]) -> dict:
    """
    Calculate Defense Coverage score (OPI Section 4.1).

    Each asset dict should have:
        fqdn: str           - domain name
        cdn: bool           - CDN detected
        waf: bool           - WAF detected
        origin_hidden: bool - origin IP not directly accessible
        rate_limiting: bool - rate-limit headers observed (optional)
        vendor: str         - protection vendor name (optional)
        scrubbing: str      - scrubbing vendor name (optional)
        has_tunnel: bool    - behind tunnel/ZTNA (optional)

    Returns dict with score (0-100) and sub-component breakdown.
    """
    total = max(len(assets), 1)

    # Sub-component 1: CDN Deployment (25%)
    cdn_count = sum(1 for a in assets if a.get("cdn"))
    cdn = round((cdn_count / total) * 100)

    # Sub-component 2: WAF Deployment (25%)
    waf_count = sum(1 for a in assets if a.get("waf"))
    rl_count = sum(1 for a in assets if a.get("rate_limiting"))
    if waf_count > 0:
        waf = round((waf_count / total) * 100)
    elif rl_count > 0:
        waf = 50
    else:
        waf = 0

    # Sub-component 3: Origin Protection (20%)
    exposed = 0
    tunnel_count = 0
    for a in assets:
        if a.get("has_tunnel"):
            tunnel_count += 1
            continue
        if a.get("cdn") and not a.get("origin_hidden", True):
            exposed += 1
        elif not a.get("cdn"):
            exposed += 1
    protected = cdn_count - exposed
    origin = round((max(0, protected) / total) * 100)

    # Sub-component 4: Rate Limiting (15%)
    rate_limit = round((rl_count / total) * 100)

    # Sub-component 5: Protection Automation (15%)
    vendor_scores = []
    has_scrubbing = False
    scrubbing_quality = 0
    for a in assets:
        vendor = (a.get("vendor") or "").lower()
        scrub = (a.get("scrubbing") or "").lower()
        for v, tier in VENDOR_AUTOMATION_TIERS.items():
            if v in vendor or v in scrub:
                vendor_scores.append(tier)
        for sv, quality in SCRUBBING_QUALITY.items():
            if sv in scrub:
                has_scrubbing = True
                scrubbing_quality = max(scrubbing_quality, quality)

    if vendor_scores:
        automation = round(sum(vendor_scores) / len(vendor_scores))
        if has_scrubbing:
            automation = min(100, automation + 10)
    else:
        automation = 0

    # Weighted sum (Section 4.1.3)
    score = round(
        cdn * 0.25 +
        waf * 0.25 +
        origin * 0.20 +
        rate_limit * 0.15 +
        automation * 0.15
    )

    return {
        "score": score,
        "cdn_deployment": cdn,
        "waf_deployment": waf,
        "origin_protection": origin,
        "rate_limiting": rate_limit,
        "protection_automation": automation,
        "has_scrubbing": has_scrubbing,
        "scrubbing_quality": scrubbing_quality,
        "tunnel_assets": tunnel_count,
    }


def l7_resilience_score(
    *,
    cdn_quality: str = "none",
    cdn_coverage: float = 0.0,
    attack_results: dict | None = None,
) -> dict:
    """
    Calculate L7 Attack Resilience score (OPI Section 4.2).

    In estimation mode (no attack_results), scores are derived from
    CDN quality and coverage ratio.

    In measured mode, pass attack_results with per-attack data:
        {
            "http_flood": {"availability": 95, "latency_factor": 80, "error_rate": 0.02},
            "slowloris": {"availability": 100, "latency_factor": 90, "error_rate": 0.0},
            ...
        }
    """
    if attack_results:
        # Measured mode: per-attack scoring (Section 4.2.3)
        attack_weights = {
            "http_flood": 0.30,
            "slowloris": 0.20,
            "resource_exhaustion": 0.20,
            "cache_bypass": 0.15,
            "api_abuse": 0.15,
        }
        weighted_sum = 0
        total_weight = 0
        per_attack = {}
        for attack, weight in attack_weights.items():
            if attack in attack_results:
                r = attack_results[attack]
                avail = r.get("availability", 0)
                latency = r.get("latency_factor", 0)
                err = r.get("error_rate", 0)
                attack_score = round(avail * 0.50 + latency * 0.30 + (1 - err) * 100 * 0.20)
                per_attack[attack] = attack_score
                weighted_sum += attack_score * weight
                total_weight += weight
        score = round(weighted_sum / max(total_weight, 0.01))
        return {"score": score, "source": "measured", "per_attack": per_attack}

    # Estimation mode
    cov = max(0.0, min(1.0, cdn_coverage))
    base = {"enterprise": 80, "standard": 55, "basic": 40, "none": 10}.get(cdn_quality, 10)
    score = round(base * cov + 10 * (1 - cov))
    return {"score": score, "source": "estimated"}


def l7_attack_surface_penalty(l7_findings: list[dict] | None = None) -> dict:
    """
    Calculate L7 DDoS-relevant penalty from passive reconnaissance (OPI Section 4.2.5).

    These penalties reflect cache-bypass vectors, amplification potential, and
    resource exhaustion paths that CDN/WAF cannot mitigate without explicit configuration.

    Args:
        l7_findings: List of finding dicts, each with a "finding_type" key.

    Returns:
        Dict with total penalty and per-finding breakdown.
    """
    if not l7_findings:
        return {"penalty": 0, "applied": [], "source": "no_l7_data"}

    from collections import Counter
    counts = Counter(f.get("finding_type", "") for f in l7_findings if isinstance(f, dict))

    penalty = 0
    applied = []

    # GraphQL introspection = complexity attacks bypass cache, expensive origin queries
    if counts.get("graphql_introspection", 0) > 0:
        penalty += 12
        applied.append({"finding": "graphql_introspection", "penalty": 12, "reason": "Complexity attacks bypass cache"})
    elif counts.get("graphql_endpoint", 0) > 5:
        penalty += 8
        applied.append({"finding": "graphql_endpoints_many", "penalty": 8, "count": counts["graphql_endpoint"], "reason": "Large uncacheable query surface"})
    elif counts.get("graphql_endpoint", 0) > 0:
        penalty += 4
        applied.append({"finding": "graphql_endpoints", "penalty": 4, "count": counts["graphql_endpoint"], "reason": "Uncacheable query surface"})

    # WordPress XMLRPC = pingback amplification (reflected DDoS)
    if counts.get("wp_xmlrpc", 0) > 0:
        penalty += 6
        applied.append({"finding": "wp_xmlrpc", "penalty": 6, "reason": "Pingback amplification vector"})

    # No rate limiting + login endpoints = unlimited auth request volume
    has_rate_limit = counts.get("rate_limit_config", 0) > 0
    login_count = counts.get("login_endpoint", 0) + counts.get("login_detected", 0)
    if not has_rate_limit and login_count > 3:
        penalty += 8
        applied.append({"finding": "no_rate_limit_with_logins", "penalty": 8, "login_count": login_count, "reason": "Unlimited auth request volume"})

    # Large uncacheable API surface = cache-bypass flood targets
    api_count = counts.get("api_endpoint_discovered", 0) + counts.get("graphql_endpoint", 0)
    if api_count > 20:
        penalty += 6
        applied.append({"finding": "large_api_surface", "penalty": 6, "api_count": api_count, "reason": "Many cache-bypass vectors"})
    elif api_count > 5:
        penalty += 3
        applied.append({"finding": "api_surface", "penalty": 3, "api_count": api_count, "reason": "Some cache-bypass vectors"})

    return {"penalty": penalty, "applied": applied, "source": "l7_recon"}


def l3l4_resilience_score(
    *,
    cdn_coverage: float = 0.0,
    has_cdn: bool = False,
    exposed_origins: int = 0,
    scrubbing_vendor: str | None = None,
    pipeline_gbps: float | None = None,
    isp_tier: str | None = None,
) -> dict:
    """
    Calculate L3/L4 Attack Resilience score (OPI Section 4.3).

    If origin is hidden behind CDN, architectural protection awards a high
    base score. Scrubbing center quality, upstream pipeline capacity, and
    ISP protection tier all feed into the calculation.
    """
    cov = max(0.0, min(1.0, cdn_coverage))
    has_scrubbing = False
    scrubbing_quality = 0
    details = {}

    if scrubbing_vendor:
        sv = scrubbing_vendor.lower()
        for vendor, quality in SCRUBBING_QUALITY.items():
            if vendor in sv:
                has_scrubbing = True
                scrubbing_quality = max(scrubbing_quality, quality)

    # Pipeline capacity tiers
    pipeline_base = None
    if pipeline_gbps is not None:
        if pipeline_gbps < 1:
            pipeline_base = 20
        elif pipeline_gbps < 10:
            pipeline_base = 40
        elif pipeline_gbps < 100:
            pipeline_base = 55
        elif pipeline_gbps < 1000:
            pipeline_base = 70
        else:
            pipeline_base = 85
        details["pipeline_gbps"] = pipeline_gbps
        details["pipeline_base"] = pipeline_base

    # ISP tier scoring
    isp_scores = {
        "none": 0, "basic": 25, "standard": 40, "premium": 55, "enterprise": 70,
    }
    isp_score = 0
    if isp_tier:
        isp_score = isp_scores.get(isp_tier.lower(), 0)
        details["isp_tier"] = isp_tier
        details["isp_score"] = isp_score

    # Determine base score
    if has_scrubbing:
        base = scrubbing_quality - (15 if exposed_origins > 0 else 0)
        if isp_score > 0:
            base = min(100, base + round(isp_score * 0.2))
        if pipeline_base is not None and pipeline_base < base:
            base = round((base + pipeline_base) / 2)
    elif isp_score > 0:
        base = isp_score - (10 if exposed_origins > 0 else 0)
        if pipeline_base is not None and pipeline_base < base:
            base = round((base + pipeline_base) / 2)
    elif pipeline_base is not None:
        base = pipeline_base - (15 if exposed_origins > 0 else 0)
    else:
        base = 85 if exposed_origins == 0 else 50

    base = max(20, base)
    score = round(base * cov + 20 * (1 - cov)) if has_cdn else base

    return {
        "score": score,
        "source": "estimated",
        "has_scrubbing": has_scrubbing,
        "scrubbing_quality": scrubbing_quality,
        **details,
    }


def protocol_resilience_score(
    *,
    cdn_quality: str = "none",
    cdn_coverage: float = 0.0,
    has_cdn: bool = False,
    attack_results: dict | None = None,
) -> dict:
    """
    Calculate Protocol Resilience score (OPI Section 4.4).

    Covers HTTP/2 (Rapid Reset, CONTINUATION Flood, PING/SETTINGS Flood)
    and HTTP/3/QUIC vulnerabilities.
    """
    if attack_results:
        h2_weights = {
            "rapid_reset": 0.35, "continuation_flood": 0.25,
            "ping_flood": 0.15, "settings_flood": 0.15, "empty_frame": 0.10,
        }
        h3_weights = {
            "initial_flood": 0.25, "cid_exhaustion": 0.25,
            "zero_rtt_replay": 0.20, "version_negotiation": 0.15, "ack_manipulation": 0.15,
        }
        scores = []
        per_attack = {}
        for name, weight in {**h2_weights, **h3_weights}.items():
            if name in attack_results:
                s = attack_results[name]
                per_attack[name] = s
                scores.append((s, weight))
        if scores:
            total_w = sum(w for _, w in scores)
            score = round(sum(s * w for s, w in scores) / max(total_w, 0.01))
            return {"score": score, "source": "measured", "per_attack": per_attack}

    # Estimation mode
    cov = max(0.0, min(1.0, cdn_coverage))
    base = 70 if cdn_quality in ("enterprise", "standard") else 30
    score = round(base * cov + 50 * (1 - cov)) if has_cdn else 50
    return {"score": score, "source": "estimated"}


def operational_resilience_score(
    *,
    cdn_quality: str = "none",
    cdn_coverage: float = 0.0,
    cdn_score: int = 0,
    has_cdn: bool = False,
    measured: dict | None = None,
) -> dict:
    """
    Calculate Operational Resilience score (OPI Section 4.5).

    In measured mode, pass:
        {"availability": 98, "latency_factor": 85, "fp_rate": 0.01, "recovery_seconds": 15}
    """
    if measured:
        avail = measured.get("availability", 0)
        latency = measured.get("latency_factor", 0)
        fp = (1 - measured.get("fp_rate", 0)) * 100
        recovery = max(0, 100 - (measured.get("recovery_seconds", 0) / 60 * 100))
        score = round(avail * 0.35 + latency * 0.25 + fp * 0.20 + recovery * 0.20)
        return {"score": score, "source": "measured"}

    cov = max(0.0, min(1.0, cdn_coverage))
    if cdn_score > 80:
        score = round(75 * cov + 30 * (1 - cov))
    elif has_cdn:
        score = round(50 * cov + 30 * (1 - cov))
    else:
        score = 30
    return {"score": score, "source": "estimated"}


# Bot detection depth scores from empirical JS RE (2026-04-03).
# Higher = vendor JS fingerprints visitors more aggressively = harder to bypass.
_VENDOR_BOT_DETECTION_DEPTH = {
    "f5": 95, "f5 shape": 95, "shape": 95,
    "vercara": 90, "neustar": 90,
    "akamai": 85, "perimeterx": 85, "human": 85,
    "sucuri": 80, "ddos-guard": 80, "ddos guard": 80,
    "imperva": 78, "incapsula": 78,
    "kasada": 75, "datadome": 70,
    "radware": 65, "fortinet": 60, "fortiweb": 60,
    "aws": 55, "cloudfront": 55, "checkpoint": 55, "check point": 55,
    "google": 50, "gcp": 50, "cloud armor": 50, "cloudflare": 50,
    "fastly": 45, "signal sciences": 45, "gcore": 45,
    "lumen": 40, "centurylink": 40,
    "citrix": 35, "netscaler": 35,
    "azure": 20, "microsoft": 20,
}


def evasion_resistance_score(
    *,
    cdn_quality: str = "none",
    cdn_coverage: float = 0.0,
    has_cdn: bool = False,
    measured: dict | None = None,
    assets: list | None = None,
) -> dict:
    """
    Calculate Evasion Resistance score (OPI Section 4.6).

    In estimated mode, uses vendor bot detection depth from JS RE data.
    In measured mode, pass booleans for each detection capability:
        {"ja3_detected": True, "ua_detected": True, "slow_detected": False,
         "ip_rotation_handled": True, "header_detected": False}
    """
    if measured:
        ja3 = 100 if measured.get("ja3_detected") else 0
        ua = 100 if measured.get("ua_detected") else 50
        slow = 100 if measured.get("slow_detected") else 30
        ip = 100 if measured.get("ip_rotation_handled") else 50
        header = 100 if measured.get("header_detected") else 50
        score = round(ja3 * 0.40 + ua * 0.20 + slow * 0.20 + ip * 0.10 + header * 0.10)
        return {"score": score, "source": "measured"}

    cov = max(0.0, min(1.0, cdn_coverage))

    # Compute average bot detection depth from detected vendors
    depths = []
    for a in (assets or []):
        for field in ("waf_provider", "cdn_provider", "appliance_vendor"):
            v = (a.get(field) or "").lower()
            if not v:
                continue
            for bv, bd in _VENDOR_BOT_DETECTION_DEPTH.items():
                if bv in v:
                    depths.append(bd)
                    break
    avg_depth = round(sum(depths) / max(len(depths), 1)) if depths else 30

    if has_cdn:
        score = round(avg_depth * cov + 10 * (1 - cov))
    else:
        score = min(avg_depth, 30)
    return {"score": score, "source": "estimated"}


def calculate_opi(
    assets: list[dict],
    cdn_quality: str = "none",
    *,
    scrubbing_vendor: str | None = None,
    pipeline_gbps: float | None = None,
    isp_tier: str | None = None,
    attack_results: dict | None = None,
    operational_measured: dict | None = None,
    evasion_measured: dict | None = None,
    l7_findings: list[dict] | None = None,
) -> dict:
    """
    Calculate complete OPI score from asset inventory and optional test data.

    Args:
        assets: List of asset dicts. Each should have:
            fqdn: str, cdn: bool, waf: bool, origin_hidden: bool,
            rate_limiting: bool (opt), vendor: str (opt), scrubbing: str (opt)
        cdn_quality: "enterprise" | "standard" | "basic" | "none"
        scrubbing_vendor: Name of scrubbing center vendor (optional)
        pipeline_gbps: Upstream link capacity in Gbps (optional)
        isp_tier: ISP DDoS protection tier (optional)
        attack_results: Dict of attack test results for L7/protocol scoring (optional)
        operational_measured: Operational test measurements (optional)
        evasion_measured: Evasion detection test results (optional)
        l7_findings: List of L7 recon finding dicts for attack surface penalties (optional, v1.1)

    Returns:
        Dict with score, grade, classification, and per-component breakdown.
    """
    total = max(len(assets), 1)
    cdn_count = sum(1 for a in assets if a.get("cdn"))
    cdn_cov = cdn_count / total
    has_cdn = cdn_quality != "none" or cdn_count > 0
    exposed = sum(
        1 for a in assets
        if a.get("cdn") and not a.get("origin_hidden", True)
    ) + sum(1 for a in assets if not a.get("cdn") and not a.get("has_tunnel"))

    # Component 1: Defense Coverage
    dc = defense_coverage_score(assets)

    # Component 2: L7 Attack Resilience
    l7_attacks = None
    if attack_results:
        l7_keys = {"http_flood", "slowloris", "resource_exhaustion", "cache_bypass", "api_abuse"}
        l7_data = {k: v for k, v in attack_results.items() if k in l7_keys}
        if l7_data:
            l7_attacks = l7_data
    l7 = l7_resilience_score(cdn_quality=cdn_quality, cdn_coverage=cdn_cov, attack_results=l7_attacks)

    # L7 Attack Surface penalties (Section 4.2.5, v1.1)
    # Applied only in Estimated tier (l7_findings present, no active test results)
    l7_surface = l7_attack_surface_penalty(l7_findings)
    if l7_surface["penalty"] > 0 and l7["source"] == "estimated":
        l7["score"] = max(0, l7["score"] - l7_surface["penalty"])
        l7["l7_surface_penalty"] = l7_surface

    # Component 3: L3/L4 Resilience
    l3l4 = l3l4_resilience_score(
        cdn_coverage=cdn_cov, has_cdn=has_cdn,
        exposed_origins=exposed, scrubbing_vendor=scrubbing_vendor,
        pipeline_gbps=pipeline_gbps, isp_tier=isp_tier,
    )

    # Component 4: Protocol Resilience
    proto_attacks = None
    if attack_results:
        proto_keys = {"rapid_reset", "continuation_flood", "ping_flood", "settings_flood",
                      "empty_frame", "initial_flood", "cid_exhaustion", "zero_rtt_replay",
                      "version_negotiation", "ack_manipulation"}
        proto_data = {k: v for k, v in attack_results.items() if k in proto_keys}
        if proto_data:
            proto_attacks = proto_data
    proto = protocol_resilience_score(
        cdn_quality=cdn_quality, cdn_coverage=cdn_cov, has_cdn=has_cdn, attack_results=proto_attacks,
    )

    # Component 5: Operational Resilience
    ops = operational_resilience_score(
        cdn_quality=cdn_quality, cdn_coverage=cdn_cov,
        cdn_score=dc["cdn_deployment"], has_cdn=has_cdn, measured=operational_measured,
    )

    # Component 6: Evasion Resistance
    evasion = evasion_resistance_score(
        cdn_quality=cdn_quality, cdn_coverage=cdn_cov, has_cdn=has_cdn, measured=evasion_measured,
    )

    # Composite score (Section 3.1)
    score = round(
        dc["score"] * WEIGHTS["defense_coverage"] +
        l7["score"] * WEIGHTS["l7_attack"] +
        l3l4["score"] * WEIGHTS["l3l4_attack"] +
        proto["score"] * WEIGHTS["protocol"] +
        ops["score"] * WEIGHTS["operational"] +
        evasion["score"] * WEIGHTS["evasion"]
    )

    g = grade_from_score(score)

    # Determine assessment tier (Section 3.4)
    has_active = attack_results or operational_measured or evasion_measured
    has_l7_recon = l7_findings is not None and len(l7_findings) > 0
    tier = "validated" if has_active else ("estimated" if has_l7_recon else "passive")

    return {
        "score": score,
        "grade": g["grade"],
        "classification": g["classification"],
        "tier": tier,
        "components": {
            "defense_coverage": dc,
            "l7_attack": l7,
            "l3l4_attack": l3l4,
            "protocol": proto,
            "operational": ops,
            "evasion": evasion,
        },
        "weights": WEIGHTS,
        "asset_count": len(assets),
        "version": "1.1.0",
    }


def normalized_opi(raw_score: int, fleet_rps: int, fleet_count: int = 1) -> float:
    """
    Normalize OPI by attack intensity (Section 6.3).

    Allows comparison across different attack scales. A target surviving
    100K RPS with OPI 70 is more resilient than one at 1K RPS with OPI 70.
    """
    intensity = math.log10(1 + fleet_rps)
    scale = math.log10(1 + fleet_count)
    return round(raw_score * (1 + intensity * 0.1 + scale * 0.05), 1)

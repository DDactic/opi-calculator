#!/usr/bin/env python3
"""
OPI Calculator CLI - Calculate DDoS resilience scores from the command line.

Usage:
    opi-calc --assets assets.json
    opi-calc --interactive
    opi-calc --example
"""

import argparse
import json
import sys

from .calculator import calculate_opi, grade_from_score, normalized_opi


GRADE_COLORS = {
    "A": "\033[92m",  # green
    "B": "\033[94m",  # blue
    "C": "\033[93m",  # yellow
    "D": "\033[33m",  # orange
    "F": "\033[91m",  # red
}
RESET = "\033[0m"
BOLD = "\033[1m"


def color_grade(grade: str) -> str:
    c = GRADE_COLORS.get(grade, "")
    return f"{c}{BOLD}{grade}{RESET}" if c else grade


def print_report(result: dict, target: str = ""):
    header = f"OPI Assessment{f' - {target}' if target else ''}"
    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}{header:^60}{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}\n")

    score = result["score"]
    grade = result["grade"]
    classification = result["classification"]
    print(f"  OPI Score:  {BOLD}{score}/100{RESET}  (Grade {color_grade(grade)} - {classification})")
    print(f"  Assets:     {result['asset_count']}")
    print()

    # Component breakdown
    print(f"  {BOLD}Component Breakdown:{RESET}")
    print(f"  {'Component':<28} {'Score':>6}  {'Weight':>6}")
    print(f"  {'-' * 44}")

    labels = {
        "defense_coverage": "Defense Coverage",
        "l7_attack": "L7 Attack Resilience",
        "l3l4_attack": "L3/L4 Resilience",
        "protocol": "Protocol Resilience",
        "operational": "Operational Resilience",
        "evasion": "Evasion Resistance",
    }

    for key, label in labels.items():
        comp = result["components"][key]
        weight = result["weights"][key]
        s = comp["score"]
        g = grade_from_score(s)["grade"]
        print(f"  {label:<28} {s:>4}/100  {weight * 100:>4.0f}%  {color_grade(g)}")

    # Defense coverage detail
    dc = result["components"]["defense_coverage"]
    print(f"\n  {BOLD}Defense Coverage Detail:{RESET}")
    print(f"    CDN Deployment:          {dc['cdn_deployment']}%")
    print(f"    WAF Deployment:          {dc['waf_deployment']}%")
    print(f"    Origin Protection:       {dc['origin_protection']}%")
    print(f"    Rate Limiting:           {dc['rate_limiting']}%")
    print(f"    Protection Automation:   {dc['protection_automation']}%")
    if dc.get("has_scrubbing"):
        print(f"    Scrubbing Quality:       {dc['scrubbing_quality']}/100")

    print(f"\n{'=' * 60}\n")


def run_interactive():
    print(f"\n{BOLD}OPI Calculator - Interactive Mode{RESET}\n")
    print("Enter asset information. Type 'done' when finished.\n")

    assets = []
    while True:
        fqdn = input("  Domain (or 'done'): ").strip()
        if fqdn.lower() == "done":
            break

        cdn = input("    CDN detected? (y/n): ").strip().lower() == "y"
        waf = input("    WAF detected? (y/n): ").strip().lower() == "y"
        origin_hidden = True
        if cdn:
            origin_hidden = input("    Origin hidden? (y/n): ").strip().lower() == "y"
        rl = input("    Rate limiting? (y/n): ").strip().lower() == "y"
        vendor = input("    Vendor (cloudflare/aws/akamai/etc, or skip): ").strip()

        asset = {
            "fqdn": fqdn,
            "cdn": cdn,
            "waf": waf,
            "origin_hidden": origin_hidden,
            "rate_limiting": rl,
        }
        if vendor:
            asset["vendor"] = vendor
        assets.append(asset)
        print()

    if not assets:
        print("No assets entered.")
        return

    print("\nCDN quality tier:")
    print("  1. enterprise  (Cloudflare Enterprise, AWS Shield Advanced)")
    print("  2. standard    (Cloudflare Pro, CloudFront)")
    print("  3. basic       (Cloudflare Free)")
    print("  4. none")
    choice = input("  Select (1-4): ").strip()
    quality_map = {"1": "enterprise", "2": "standard", "3": "basic", "4": "none"}
    cdn_quality = quality_map.get(choice, "none")

    result = calculate_opi(assets, cdn_quality)
    print_report(result)


def run_example():
    print(f"\n{BOLD}OPI Calculator - Example Scenarios{RESET}\n")

    scenarios = [
        {
            "name": "Unprotected Origin Server",
            "assets": [
                {"fqdn": "www.example.com", "cdn": False, "waf": False, "origin_hidden": False},
                {"fqdn": "api.example.com", "cdn": False, "waf": False, "origin_hidden": False},
            ],
            "cdn_quality": "none",
        },
        {
            "name": "CDN-Only (No WAF)",
            "assets": [
                {"fqdn": "www.example.com", "cdn": True, "waf": False, "origin_hidden": True, "vendor": "cloudflare"},
                {"fqdn": "api.example.com", "cdn": True, "waf": False, "origin_hidden": False, "vendor": "cloudflare"},
                {"fqdn": "mail.example.com", "cdn": False, "waf": False, "origin_hidden": False},
            ],
            "cdn_quality": "basic",
        },
        {
            "name": "Enterprise Stack (CDN + WAF + Scrubbing)",
            "assets": [
                {"fqdn": "www.example.com", "cdn": True, "waf": True, "origin_hidden": True, "vendor": "cloudflare", "rate_limiting": True},
                {"fqdn": "app.example.com", "cdn": True, "waf": True, "origin_hidden": True, "vendor": "cloudflare", "rate_limiting": True},
                {"fqdn": "api.example.com", "cdn": True, "waf": True, "origin_hidden": True, "vendor": "cloudflare", "rate_limiting": True},
                {"fqdn": "admin.example.com", "cdn": True, "waf": True, "origin_hidden": True, "vendor": "cloudflare"},
            ],
            "cdn_quality": "enterprise",
        },
    ]

    for scenario in scenarios:
        print(f"\n{BOLD}--- {scenario['name']} ---{RESET}")
        result = calculate_opi(scenario["assets"], scenario["cdn_quality"])
        print_report(result, scenario["name"])


def main():
    parser = argparse.ArgumentParser(
        description="OPI Calculator - Open Protection Index scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  opi-calc --example              Run example scenarios\n"
            "  opi-calc --interactive           Interactive asset entry\n"
            "  opi-calc --assets inventory.json Score from JSON file\n"
            "  opi-calc --assets inv.json --cdn-quality enterprise\n"
        ),
    )
    parser.add_argument("--assets", help="JSON file with asset inventory")
    parser.add_argument("--cdn-quality", choices=["enterprise", "standard", "basic", "none"],
                        default="none", help="CDN quality tier (default: none)")
    parser.add_argument("--scrubbing-vendor", help="Scrubbing center vendor name")
    parser.add_argument("--pipeline-gbps", type=float, help="Upstream link capacity in Gbps")
    parser.add_argument("--isp-tier", choices=["none", "basic", "standard", "premium", "enterprise"],
                        help="ISP DDoS protection tier")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("--example", action="store_true", help="Run example scenarios")
    parser.add_argument("--target", default="", help="Target name for the report header")

    args = parser.parse_args()

    if args.example:
        run_example()
        return

    if args.interactive:
        run_interactive()
        return

    if not args.assets:
        parser.print_help()
        print("\nError: --assets, --interactive, or --example is required.")
        sys.exit(1)

    with open(args.assets) as f:
        data = json.load(f)

    assets = data if isinstance(data, list) else data.get("assets", [])
    cdn_quality = data.get("cdn_quality", args.cdn_quality) if isinstance(data, dict) else args.cdn_quality

    result = calculate_opi(
        assets, cdn_quality,
        scrubbing_vendor=args.scrubbing_vendor,
        pipeline_gbps=args.pipeline_gbps,
        isp_tier=args.isp_tier,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result, args.target or data.get("target", ""))


if __name__ == "__main__":
    main()

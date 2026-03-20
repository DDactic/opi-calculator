"""Tests for OPI Calculator."""

import pytest
from opi_calculator import (
    calculate_opi,
    defense_coverage_score,
    grade_from_score,
    l7_resilience_score,
    l3l4_resilience_score,
    evasion_resistance_score,
    WEIGHTS,
)


class TestGradeFromScore:
    def test_grade_a(self):
        assert grade_from_score(95)["grade"] == "A"
        assert grade_from_score(90)["grade"] == "A"

    def test_grade_b(self):
        assert grade_from_score(85)["grade"] == "B"
        assert grade_from_score(80)["grade"] == "B"

    def test_grade_c(self):
        assert grade_from_score(75)["grade"] == "C"

    def test_grade_d(self):
        assert grade_from_score(65)["grade"] == "D"

    def test_grade_f(self):
        assert grade_from_score(50)["grade"] == "F"
        assert grade_from_score(0)["grade"] == "F"


class TestWeights:
    def test_weights_sum_to_one(self):
        assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-10


class TestDefenseCoverage:
    def test_no_protection(self):
        assets = [
            {"fqdn": "a.com", "cdn": False, "waf": False, "origin_hidden": False},
            {"fqdn": "b.com", "cdn": False, "waf": False, "origin_hidden": False},
        ]
        result = defense_coverage_score(assets)
        assert result["score"] == 0
        assert result["cdn_deployment"] == 0
        assert result["waf_deployment"] == 0

    def test_full_protection(self):
        assets = [
            {"fqdn": "a.com", "cdn": True, "waf": True, "origin_hidden": True,
             "rate_limiting": True, "vendor": "cloudflare"},
        ]
        result = defense_coverage_score(assets)
        assert result["score"] >= 80
        assert result["cdn_deployment"] == 100
        assert result["waf_deployment"] == 100

    def test_partial_cdn(self):
        assets = [
            {"fqdn": "a.com", "cdn": True, "waf": False, "origin_hidden": True},
            {"fqdn": "b.com", "cdn": False, "waf": False, "origin_hidden": False},
        ]
        result = defense_coverage_score(assets)
        assert result["cdn_deployment"] == 50

    def test_rate_limiting_fallback(self):
        assets = [
            {"fqdn": "a.com", "cdn": False, "waf": False, "rate_limiting": True},
        ]
        result = defense_coverage_score(assets)
        assert result["waf_deployment"] == 50  # rate-limiting fallback

    def test_vendor_automation(self):
        assets = [
            {"fqdn": "a.com", "cdn": True, "waf": True, "origin_hidden": True, "vendor": "cloudflare"},
        ]
        result = defense_coverage_score(assets)
        assert result["protection_automation"] == 100

    def test_scrubbing_detection(self):
        assets = [
            {"fqdn": "a.com", "cdn": True, "waf": True, "origin_hidden": True, "scrubbing": "radware"},
        ]
        result = defense_coverage_score(assets)
        assert result["has_scrubbing"] is True
        assert result["scrubbing_quality"] == 90


class TestL7Resilience:
    def test_no_cdn(self):
        result = l7_resilience_score(cdn_quality="none", cdn_coverage=0.0)
        assert result["score"] == 10
        assert result["source"] == "estimated"

    def test_enterprise_cdn(self):
        result = l7_resilience_score(cdn_quality="enterprise", cdn_coverage=1.0)
        assert result["score"] == 80

    def test_partial_coverage(self):
        result = l7_resilience_score(cdn_quality="standard", cdn_coverage=0.5)
        # 55 * 0.5 + 10 * 0.5 = 32.5 -> 32
        assert result["score"] == 32

    def test_measured_mode(self):
        attacks = {
            "http_flood": {"availability": 100, "latency_factor": 90, "error_rate": 0.01},
        }
        result = l7_resilience_score(attack_results=attacks)
        assert result["source"] == "measured"
        assert result["score"] > 0


class TestL3L4Resilience:
    def test_hidden_origin(self):
        result = l3l4_resilience_score(
            cdn_coverage=1.0, has_cdn=True, exposed_origins=0,
        )
        assert result["score"] == 85

    def test_exposed_origin(self):
        result = l3l4_resilience_score(
            cdn_coverage=0.0, has_cdn=False, exposed_origins=2,
        )
        assert result["score"] == 50

    def test_with_scrubbing(self):
        result = l3l4_resilience_score(
            cdn_coverage=1.0, has_cdn=True, exposed_origins=0,
            scrubbing_vendor="radware",
        )
        assert result["has_scrubbing"] is True
        assert result["score"] >= 85

    def test_pipeline_capacity(self):
        low = l3l4_resilience_score(pipeline_gbps=0.5)
        high = l3l4_resilience_score(pipeline_gbps=500)
        assert high["score"] > low["score"]


class TestEvasionResistance:
    def test_no_protection(self):
        result = evasion_resistance_score(cdn_quality="none")
        assert result["score"] == 10

    def test_measured_full_detection(self):
        result = evasion_resistance_score(measured={
            "ja3_detected": True, "ua_detected": True, "slow_detected": True,
            "ip_rotation_handled": True, "header_detected": True,
        })
        assert result["score"] == 100

    def test_measured_no_ja3(self):
        result = evasion_resistance_score(measured={
            "ja3_detected": False, "ua_detected": True, "slow_detected": True,
            "ip_rotation_handled": True, "header_detected": True,
        })
        assert result["score"] == 60  # Missing 40pts from JA3


class TestCalculateOPI:
    def test_unprotected(self):
        assets = [
            {"fqdn": "a.com", "cdn": False, "waf": False},
            {"fqdn": "b.com", "cdn": False, "waf": False},
        ]
        result = calculate_opi(assets, "none")
        assert result["grade"] == "F"
        assert result["score"] < 40
        assert result["asset_count"] == 2

    def test_enterprise(self):
        assets = [
            {"fqdn": "a.com", "cdn": True, "waf": True, "origin_hidden": True,
             "rate_limiting": True, "vendor": "cloudflare"},
            {"fqdn": "b.com", "cdn": True, "waf": True, "origin_hidden": True,
             "rate_limiting": True, "vendor": "cloudflare"},
        ]
        result = calculate_opi(assets, "enterprise")
        assert result["grade"] in ("A", "B")
        assert result["score"] >= 75

    def test_components_present(self):
        assets = [{"fqdn": "a.com", "cdn": True, "waf": True, "origin_hidden": True}]
        result = calculate_opi(assets, "standard")
        assert "defense_coverage" in result["components"]
        assert "l7_attack" in result["components"]
        assert "l3l4_attack" in result["components"]
        assert "protocol" in result["components"]
        assert "operational" in result["components"]
        assert "evasion" in result["components"]

    def test_weights_in_result(self):
        assets = [{"fqdn": "a.com", "cdn": False, "waf": False}]
        result = calculate_opi(assets, "none")
        assert result["weights"] == WEIGHTS

    def test_score_range(self):
        for cdn_q in ["none", "basic", "standard", "enterprise"]:
            assets = [{"fqdn": "a.com", "cdn": cdn_q != "none", "waf": cdn_q == "enterprise",
                        "origin_hidden": cdn_q != "none", "vendor": "cloudflare"}]
            result = calculate_opi(assets, cdn_q)
            assert 0 <= result["score"] <= 100


class TestNormalizedOPI:
    def test_normalization_increases_with_rps(self):
        from opi_calculator.calculator import normalized_opi
        low = normalized_opi(70, 1000)
        high = normalized_opi(70, 100000)
        assert high > low

    def test_normalization_increases_with_fleet(self):
        from opi_calculator.calculator import normalized_opi
        single = normalized_opi(70, 10000, 1)
        fleet = normalized_opi(70, 10000, 100)
        assert fleet > single

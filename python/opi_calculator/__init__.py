"""OPI Calculator - Open Protection Index scoring library."""

from .calculator import (
    calculate_opi,
    defense_coverage_score,
    l7_resilience_score,
    l7_attack_surface_penalty,
    l3l4_resilience_score,
    protocol_resilience_score,
    operational_resilience_score,
    evasion_resistance_score,
    grade_from_score,
    WEIGHTS,
    GRADE_SCALE,
)

__version__ = "1.2.0"
__all__ = [
    "calculate_opi",
    "defense_coverage_score",
    "l7_resilience_score",
    "l7_attack_surface_penalty",
    "l3l4_resilience_score",
    "protocol_resilience_score",
    "operational_resilience_score",
    "evasion_resistance_score",
    "grade_from_score",
    "WEIGHTS",
    "GRADE_SCALE",
]

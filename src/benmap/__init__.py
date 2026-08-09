"""Benmap: explainable distribution analysis for network reconnaissance."""

from .analysis import (
    BENFORD_PROBABILITIES,
    AnalysisResult,
    EligibilityPolicy,
    analyze_values,
    leading_digit,
)

__all__ = [
    "BENFORD_PROBABILITIES",
    "AnalysisResult",
    "EligibilityPolicy",
    "analyze_values",
    "leading_digit",
]

__version__ = "0.1.0"

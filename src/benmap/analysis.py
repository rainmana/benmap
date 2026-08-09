"""Benford eligibility checks and descriptive statistics.

The module deliberately separates *eligibility* from *deviation*. A population that
fails the eligibility gate is not labelled conforming or anomalous; Benford metrics
are left unset and the caller receives concrete reasons instead.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from math import ceil, isfinite, log10, log2, pi
from typing import Iterable

BENFORD_PROBABILITIES: tuple[float, ...] = tuple(
    log10(1.0 + (1.0 / digit)) for digit in range(1, 10)
)


@dataclass(frozen=True, slots=True)
class EligibilityPolicy:
    """Controls when classical first-digit Benford analysis is evaluated."""

    min_samples: int = 200
    min_orders_of_magnitude: float = 2.0
    min_unique_values: int = 9
    min_unique_ratio: float = 0.05
    min_expected_per_digit: float = 5.0

    def __post_init__(self) -> None:
        if self.min_samples < 1:
            raise ValueError("min_samples must be at least 1")
        if self.min_orders_of_magnitude < 0:
            raise ValueError("min_orders_of_magnitude must be non-negative")
        if self.min_unique_values < 1:
            raise ValueError("min_unique_values must be at least 1")
        if not 0.0 <= self.min_unique_ratio <= 1.0:
            raise ValueError("min_unique_ratio must be between 0 and 1")
        if self.min_expected_per_digit <= 0:
            raise ValueError("min_expected_per_digit must be positive")


@dataclass(frozen=True, slots=True)
class DigitBin:
    digit: int
    count: int
    observed_probability: float
    expected_probability: float
    delta_percentage_points: float


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    feature: str
    input_count: int
    sample_count: int
    excluded_count: int
    eligible: bool
    reasons: tuple[str, ...]
    min_value: float | None
    max_value: float | None
    orders_of_magnitude: float | None
    unique_values: int
    unique_ratio: float | None
    duplicate_ratio: float | None
    dominant_value: float | None
    dominant_share: float | None
    digit_distribution: tuple[DigitBin, ...]
    mad: float | None
    js_divergence: float | None
    chi_square: float | None
    largest_deviation_digit: int | None
    largest_deviation_percentage_points: float | None
    scale_mad_range: float | None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""

        return asdict(self)


def leading_digit(value: float) -> int:
    """Return the first significant decimal digit of a positive finite value."""

    number = float(value)
    if not isfinite(number) or number <= 0:
        raise ValueError("leading_digit requires a positive finite value")

    exponent = int(log10(number) // 1)
    normalized = number / (10.0**exponent)
    digit = int(normalized)

    # Floating-point rounding near a power-of-ten boundary can produce 10 or 0.
    if digit == 10:
        digit = 1
    if not 1 <= digit <= 9:
        raise ValueError(f"could not derive a leading digit from {value!r}")
    return digit


def _digit_counts(values: list[float]) -> tuple[int, ...]:
    counts = [0] * 9
    for value in values:
        counts[leading_digit(value) - 1] += 1
    return tuple(counts)


def _mad(counts: tuple[int, ...], sample_count: int) -> float:
    return sum(
        abs((count / sample_count) - expected)
        for count, expected in zip(counts, BENFORD_PROBABILITIES, strict=True)
    ) / 9.0


def _js_divergence(counts: tuple[int, ...], sample_count: int) -> float:
    observed = tuple(count / sample_count for count in counts)
    midpoint = tuple(
        (actual + expected) / 2.0
        for actual, expected in zip(observed, BENFORD_PROBABILITIES, strict=True)
    )

    def kl_term(probability: float, middle: float) -> float:
        if probability == 0.0:
            return 0.0
        return probability * log2(probability / middle)

    observed_kl = sum(
        kl_term(actual, middle)
        for actual, middle in zip(observed, midpoint, strict=True)
    )
    expected_kl = sum(
        kl_term(expected, middle)
        for expected, middle in zip(
            BENFORD_PROBABILITIES, midpoint, strict=True
        )
    )
    return 0.5 * (observed_kl + expected_kl)


def _chi_square(counts: tuple[int, ...], sample_count: int) -> float:
    statistic = 0.0
    for count, probability in zip(counts, BENFORD_PROBABILITIES, strict=True):
        expected = sample_count * probability
        statistic += ((count - expected) ** 2) / expected
    return statistic


def _scale_mad_range(values: list[float]) -> float:
    factors = (0.1, 1.0, 2.0, pi, 10.0)
    scores = [
        _mad(_digit_counts([value * factor for value in values]), len(values))
        for factor in factors
    ]
    return max(scores) - min(scores)


def analyze_values(
    values: Iterable[float | int | None],
    *,
    feature: str,
    policy: EligibilityPolicy | None = None,
) -> AnalysisResult:
    """Evaluate eligibility and, when justified, first-digit Benford deviation.

    ``None``, non-finite values, zero, and negative values are counted as excluded.
    The function still reports ordinary distribution diagnostics when the Benford
    eligibility gate fails.
    """

    active_policy = policy or EligibilityPolicy()
    materialized = list(values)
    clean_values: list[float] = []

    for candidate in materialized:
        if candidate is None:
            continue
        try:
            number = float(candidate)
        except (TypeError, ValueError):
            continue
        if isfinite(number) and number > 0:
            clean_values.append(number)

    input_count = len(materialized)
    sample_count = len(clean_values)
    excluded_count = input_count - sample_count

    if sample_count == 0:
        return AnalysisResult(
            feature=feature,
            input_count=input_count,
            sample_count=0,
            excluded_count=excluded_count,
            eligible=False,
            reasons=("no positive finite observations",),
            min_value=None,
            max_value=None,
            orders_of_magnitude=None,
            unique_values=0,
            unique_ratio=None,
            duplicate_ratio=None,
            dominant_value=None,
            dominant_share=None,
            digit_distribution=(),
            mad=None,
            js_divergence=None,
            chi_square=None,
            largest_deviation_digit=None,
            largest_deviation_percentage_points=None,
            scale_mad_range=None,
        )

    minimum = min(clean_values)
    maximum = max(clean_values)
    orders = log10(maximum / minimum) if maximum > minimum else 0.0

    value_counts = Counter(clean_values)
    unique_values = len(value_counts)
    unique_ratio = unique_values / sample_count
    duplicate_ratio = 1.0 - unique_ratio
    dominant_value, dominant_count = value_counts.most_common(1)[0]
    dominant_share = dominant_count / sample_count

    counts = _digit_counts(clean_values)
    bins = tuple(
        DigitBin(
            digit=digit,
            count=counts[digit - 1],
            observed_probability=counts[digit - 1] / sample_count,
            expected_probability=BENFORD_PROBABILITIES[digit - 1],
            delta_percentage_points=(
                (counts[digit - 1] / sample_count)
                - BENFORD_PROBABILITIES[digit - 1]
            )
            * 100.0,
        )
        for digit in range(1, 10)
    )

    reasons: list[str] = []
    required_for_expected_counts = ceil(
        active_policy.min_expected_per_digit / BENFORD_PROBABILITIES[-1]
    )
    required_samples = max(active_policy.min_samples, required_for_expected_counts)

    if sample_count < required_samples:
        reasons.append(
            f"sample count {sample_count} is below required {required_samples}"
        )
    if orders < active_policy.min_orders_of_magnitude:
        reasons.append(
            "numeric span "
            f"{orders:.3f} orders is below required "
            f"{active_policy.min_orders_of_magnitude:.3f}"
        )
    if unique_values < active_policy.min_unique_values:
        reasons.append(
            f"unique value count {unique_values} is below required "
            f"{active_policy.min_unique_values}"
        )
    if unique_ratio < active_policy.min_unique_ratio:
        reasons.append(
            f"unique ratio {unique_ratio:.3f} is below required "
            f"{active_policy.min_unique_ratio:.3f}"
        )

    eligible = not reasons
    if not eligible:
        return AnalysisResult(
            feature=feature,
            input_count=input_count,
            sample_count=sample_count,
            excluded_count=excluded_count,
            eligible=False,
            reasons=tuple(reasons),
            min_value=minimum,
            max_value=maximum,
            orders_of_magnitude=orders,
            unique_values=unique_values,
            unique_ratio=unique_ratio,
            duplicate_ratio=duplicate_ratio,
            dominant_value=dominant_value,
            dominant_share=dominant_share,
            digit_distribution=bins,
            mad=None,
            js_divergence=None,
            chi_square=None,
            largest_deviation_digit=None,
            largest_deviation_percentage_points=None,
            scale_mad_range=None,
        )

    mad = _mad(counts, sample_count)
    js_divergence = _js_divergence(counts, sample_count)
    chi_square = _chi_square(counts, sample_count)
    largest_bin = max(bins, key=lambda item: abs(item.delta_percentage_points))

    return AnalysisResult(
        feature=feature,
        input_count=input_count,
        sample_count=sample_count,
        excluded_count=excluded_count,
        eligible=True,
        reasons=(),
        min_value=minimum,
        max_value=maximum,
        orders_of_magnitude=orders,
        unique_values=unique_values,
        unique_ratio=unique_ratio,
        duplicate_ratio=duplicate_ratio,
        dominant_value=dominant_value,
        dominant_share=dominant_share,
        digit_distribution=bins,
        mad=mad,
        js_divergence=js_divergence,
        chi_square=chi_square,
        largest_deviation_digit=largest_bin.digit,
        largest_deviation_percentage_points=largest_bin.delta_percentage_points,
        scale_mad_range=_scale_mad_range(clean_values),
    )

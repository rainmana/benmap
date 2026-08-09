from __future__ import annotations

import unittest
from math import isclose

from benmap.analysis import (
    BENFORD_PROBABILITIES,
    EligibilityPolicy,
    analyze_values,
    leading_digit,
)


class AnalysisTests(unittest.TestCase):
    def test_benford_probabilities_sum_to_one(self) -> None:
        self.assertTrue(isclose(sum(BENFORD_PROBABILITIES), 1.0, abs_tol=1e-12))
        self.assertGreater(BENFORD_PROBABILITIES[0], BENFORD_PROBABILITIES[-1])

    def test_leading_digit_handles_small_and_large_values(self) -> None:
        self.assertEqual(leading_digit(0.00421), 4)
        self.assertEqual(leading_digit(987654), 9)
        self.assertEqual(leading_digit(1000), 1)

    def test_invalid_leading_digit_values_raise(self) -> None:
        for value in (0, -1, float("inf"), float("nan")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                leading_digit(value)

    def test_benford_shaped_population_is_eligible(self) -> None:
        target_count = 3000
        counts = [
            round(probability * target_count)
            for probability in BENFORD_PROBABILITIES
        ]
        counts[0] += target_count - sum(counts)

        values: list[float] = []
        for digit, count in enumerate(counts, start=1):
            for index in range(count):
                fraction = ((index % 89) + 1) / 100.0
                exponent = index % 5
                values.append((digit + fraction) * (10**exponent))

        result = analyze_values(values, feature="synthetic")

        self.assertTrue(result.eligible, result.reasons)
        self.assertIsNotNone(result.mad)
        self.assertLess(result.mad or 1.0, 0.002)
        self.assertEqual(result.sample_count, target_count)
        self.assertGreaterEqual(result.orders_of_magnitude or 0, 4.0)

    def test_homogeneous_population_is_not_benford_eligible(self) -> None:
        result = analyze_values([4096] * 250, feature="content_length")

        self.assertFalse(result.eligible)
        self.assertIsNone(result.mad)
        self.assertEqual(result.unique_values, 1)
        self.assertEqual(result.dominant_share, 1.0)
        self.assertTrue(any("numeric span" in reason for reason in result.reasons))
        self.assertTrue(
            any("unique value count" in reason for reason in result.reasons)
        )

    def test_missing_and_nonpositive_values_are_excluded(self) -> None:
        policy = EligibilityPolicy(
            min_samples=1,
            min_orders_of_magnitude=0,
            min_unique_values=1,
            min_unique_ratio=0,
            min_expected_per_digit=0.01,
        )
        result = analyze_values(
            [None, 0, -1, float("nan"), 123],
            feature="test",
            policy=policy,
        )

        self.assertEqual(result.input_count, 5)
        self.assertEqual(result.sample_count, 1)
        self.assertEqual(result.excluded_count, 4)
        self.assertTrue(result.eligible)

    def test_power_of_ten_scaling_preserves_digit_counts(self) -> None:
        values = [1.2, 2.3, 4.5, 9.9] * 100
        policy = EligibilityPolicy(
            min_samples=1,
            min_orders_of_magnitude=0,
            min_unique_values=1,
            min_unique_ratio=0,
            min_expected_per_digit=0.01,
        )

        original = analyze_values(values, feature="x", policy=policy)
        scaled = analyze_values(
            [value * 1000 for value in values], feature="x", policy=policy
        )

        self.assertEqual(
            [bucket.count for bucket in original.digit_distribution],
            [bucket.count for bucket in scaled.digit_distribution],
        )


if __name__ == "__main__":
    unittest.main()

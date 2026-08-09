"""Command-line entry point for Benmap."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import fields
from pathlib import Path
from xml.etree import ElementTree as ET

from .analysis import AnalysisResult, EligibilityPolicy, analyze_values
from .nmap_xml import FEATURES, Observation, extract_feature_values, parse_nmap_xml


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="benmap",
        description=(
            "Analyze response-derived network measurements without treating "
            "Benford's law as a maliciousness oracle."
        ),
    )
    parser.add_argument("--version", action="version", version="benmap 0.1.0")

    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser(
        "analyze", help="analyze one feature from Nmap XML"
    )
    analyze.add_argument("xml", type=Path, help="Nmap -oX output file")
    analyze.add_argument(
        "--feature",
        choices=FEATURES,
        default="content_length",
        help="numeric observation to evaluate (default: content_length)",
    )
    analyze.add_argument("--min-samples", type=int, default=200)
    analyze.add_argument("--min-orders", type=float, default=2.0)
    analyze.add_argument("--min-unique-values", type=int, default=9)
    analyze.add_argument("--min-unique-ratio", type=float, default=0.05)
    analyze.add_argument(
        "--format", choices=("text", "json"), default="text"
    )

    observations = commands.add_parser(
        "observations", help="export structured NSE observations"
    )
    observations.add_argument("xml", type=Path, help="Nmap -oX output file")
    observations.add_argument(
        "--format", choices=("json", "jsonl", "csv"), default="jsonl"
    )

    return parser


def _format_number(value: float | None, digits: int = 6) -> str:
    if value is None:
        return "not evaluated"
    return f"{value:.{digits}f}"


def _render_text(result: AnalysisResult, *, source: Path) -> str:
    lines = [
        "Benmap analysis",
        f"  source: {source}",
        f"  feature: {result.feature}",
        f"  observations: {result.input_count}",
        f"  positive finite samples: {result.sample_count}",
        f"  excluded: {result.excluded_count}",
        f"  Benford eligible: {'yes' if result.eligible else 'no'}",
    ]

    if result.reasons:
        lines.append("  eligibility reasons:")
        lines.extend(f"    - {reason}" for reason in result.reasons)

    lines.extend(
        [
            f"  numeric span (orders): {_format_number(result.orders_of_magnitude, 3)}",
            f"  unique ratio: {_format_number(result.unique_ratio, 3)}",
            f"  duplicate ratio: {_format_number(result.duplicate_ratio, 3)}",
            "  dominant value: "
            + (
                str(result.dominant_value)
                if result.dominant_value is not None
                else "n/a"
            ),
            f"  dominant share: {_format_number(result.dominant_share, 3)}",
            f"  MAD: {_format_number(result.mad)}",
            f"  Jensen-Shannon divergence: {_format_number(result.js_divergence)}",
            f"  chi-square (df=8): {_format_number(result.chi_square, 3)}",
            f"  scale MAD range: {_format_number(result.scale_mad_range)}",
        ]
    )

    if result.largest_deviation_digit is not None:
        lines.append(
            "  largest digit deviation: "
            f"{result.largest_deviation_digit} "
            f"({result.largest_deviation_percentage_points:+.3f} percentage points)"
        )

    if result.digit_distribution:
        lines.append("")
        lines.append("  digit  count  observed   expected   delta(pp)")
        for bucket in result.digit_distribution:
            lines.append(
                f"  {bucket.digit:>5}  {bucket.count:>5}  "
                f"{bucket.observed_probability:>8.4f}   "
                f"{bucket.expected_probability:>8.4f}   "
                f"{bucket.delta_percentage_points:>+9.3f}"
            )

    lines.extend(
        [
            "",
            "Interpretation: this is a distribution diagnostic, "
            "not evidence of compromise.",
        ]
    )
    return "\n".join(lines)


def _write_observations(
    observations: list[Observation], output_format: str
) -> None:
    records = [observation.to_dict() for observation in observations]
    if output_format == "json":
        print(json.dumps(records, indent=2, sort_keys=True))
        return
    if output_format == "jsonl":
        for record in records:
            print(json.dumps(record, sort_keys=True))
        return

    field_names = [field.name for field in fields(Observation)]
    writer = csv.DictWriter(sys.stdout, fieldnames=field_names)
    writer.writeheader()
    writer.writerows(records)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        observations = parse_nmap_xml(args.xml)
        if not observations:
            raise ValueError(
                "no port-level benmap-http observations were found in the XML"
            )

        if args.command == "observations":
            _write_observations(observations, args.format)
            return 0

        policy = EligibilityPolicy(
            min_samples=args.min_samples,
            min_orders_of_magnitude=args.min_orders,
            min_unique_values=args.min_unique_values,
            min_unique_ratio=args.min_unique_ratio,
        )
        values = extract_feature_values(observations, args.feature)
        result = analyze_values(values, feature=args.feature, policy=policy)

        if args.format == "json":
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        else:
            print(_render_text(result, source=args.xml))
        return 0
    except (OSError, ET.ParseError, ValueError) as error:
        print(f"benmap: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

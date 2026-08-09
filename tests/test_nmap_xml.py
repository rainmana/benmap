from __future__ import annotations

import unittest
from pathlib import Path

from benmap.nmap_xml import extract_feature_values, parse_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "nmap-benmap.xml"


class NmapXmlTests(unittest.TestCase):
    def test_parse_port_level_observation(self) -> None:
        observations = parse_nmap_xml(FIXTURE)

        self.assertEqual(len(observations), 1)
        observation = observations[0]
        self.assertEqual(observation.target, "192.0.2.10")
        self.assertEqual(observation.hostname, "fixture.example")
        self.assertEqual(observation.port, 443)
        self.assertTrue(observation.tls)
        self.assertTrue(observation.success)
        self.assertEqual(observation.content_length, 4096)
        self.assertEqual(observation.elapsed_us, 18421)
        self.assertTrue(observation.fallback_used)

    def test_postscript_summary_is_not_parsed_as_observation(self) -> None:
        observations = parse_nmap_xml(FIXTURE)
        self.assertEqual(len(observations), 1)

    def test_feature_extraction_preserves_observation_count(self) -> None:
        observations = parse_nmap_xml(FIXTURE)
        self.assertEqual(extract_feature_values(observations, "body_bytes"), [4096])

    def test_unknown_feature_is_rejected(self) -> None:
        observations = parse_nmap_xml(FIXTURE)
        with self.assertRaises(ValueError):
            extract_feature_values(observations, "port")


if __name__ == "__main__":
    unittest.main()

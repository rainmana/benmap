from __future__ import annotations

import argparse
from pathlib import Path

from benmap.nmap_xml import parse_nmap_xml


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("xml", type=Path)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    observations = parse_nmap_xml(args.xml)
    assert observations, "Nmap XML did not contain a benmap-http port observation"

    observation = next(
        (item for item in observations if item.port == args.port),
        None,
    )
    assert observation is not None, f"no observation found for TCP/{args.port}"
    assert observation.success, observation.error
    assert observation.status == 200
    assert observation.method == "GET"
    assert observation.content_length == 4096
    assert observation.body_bytes == 4096
    assert observation.elapsed_us is not None and observation.elapsed_us > 0


if __name__ == "__main__":
    main()

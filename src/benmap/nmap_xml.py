"""Parse structured ``benmap-http`` observations from Nmap XML output."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final
from xml.etree import ElementTree as ET

SCRIPT_ID: Final[str] = "benmap-http"
FEATURES: Final[tuple[str, ...]] = (
    "elapsed_us",
    "total_elapsed_us",
    "content_length",
    "body_bytes",
    "raw_body_bytes",
    "nmap_srtt_us",
    "nmap_rttvar_us",
    "nmap_timeout_us",
)


@dataclass(frozen=True, slots=True)
class Observation:
    schema: str | None
    target: str
    hostname: str | None
    port: int
    protocol: str
    service: str | None
    tls: bool
    path: str | None
    method: str | None
    success: bool
    status: int | None
    error: str | None
    elapsed_us: int | None
    total_elapsed_us: int | None
    content_length: int | None
    body_bytes: int | None
    raw_body_bytes: int | None
    body_bytes_observed: int | None
    raw_body_bytes_observed: int | None
    body_truncated: bool
    nmap_srtt_us: int | None
    nmap_rttvar_us: int | None
    nmap_timeout_us: int | None
    content_type: str | None
    server: str | None
    fallback_used: bool
    attempts: int | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _first_address(host: ET.Element) -> str | None:
    for kind in ("ipv4", "ipv6"):
        address = host.find(f"address[@addrtype='{kind}']")
        if address is not None and address.get("addr"):
            return address.get("addr")
    address = host.find("address")
    return address.get("addr") if address is not None else None


def _first_hostname(host: ET.Element) -> str | None:
    hostname = host.find("./hostnames/hostname")
    return hostname.get("name") if hostname is not None else None


def _direct_elements(script: ET.Element) -> dict[str, str]:
    fields: dict[str, str] = {}
    for element in script.findall("./elem"):
        key = element.get("key")
        if key:
            fields[key] = element.text or ""
    return fields


def _as_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str | None) -> int | None:
    if value is None or value.strip() == "":
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def parse_nmap_xml(path: str | Path) -> list[Observation]:
    """Return port-level observations emitted by ``benmap-http.nse``."""

    document = ET.parse(Path(path))
    observations: list[Observation] = []

    for host in document.getroot().findall("./host"):
        host_address = _first_address(host)
        host_name = _first_hostname(host)

        for port_element in host.findall("./ports/port"):
            script = port_element.find(f"script[@id='{SCRIPT_ID}']")
            if script is None:
                continue

            fields = _direct_elements(script)
            target = fields.get("target") or host_address
            if target is None:
                continue

            port_value = _as_int(fields.get("port") or port_element.get("portid"))
            if port_value is None:
                continue

            service_element = port_element.find("service")
            service = fields.get("service")
            if not service and service_element is not None:
                service = service_element.get("name")

            observations.append(
                Observation(
                    schema=fields.get("schema"),
                    target=target,
                    hostname=fields.get("hostname") or host_name,
                    port=port_value,
                    protocol=(
                        fields.get("protocol")
                        or port_element.get("protocol")
                        or "tcp"
                    ),
                    service=service,
                    tls=_as_bool(fields.get("tls")),
                    path=fields.get("path"),
                    method=fields.get("method"),
                    success=_as_bool(fields.get("success")),
                    status=_as_int(fields.get("status")),
                    error=fields.get("error"),
                    elapsed_us=_as_int(fields.get("elapsed_us")),
                    total_elapsed_us=_as_int(fields.get("total_elapsed_us")),
                    content_length=_as_int(fields.get("content_length")),
                    body_bytes=_as_int(fields.get("body_bytes")),
                    raw_body_bytes=_as_int(fields.get("raw_body_bytes")),
                    body_bytes_observed=_as_int(
                        fields.get("body_bytes_observed")
                    ),
                    raw_body_bytes_observed=_as_int(
                        fields.get("raw_body_bytes_observed")
                    ),
                    body_truncated=_as_bool(fields.get("body_truncated")),
                    nmap_srtt_us=_as_int(fields.get("nmap_srtt_us")),
                    nmap_rttvar_us=_as_int(fields.get("nmap_rttvar_us")),
                    nmap_timeout_us=_as_int(fields.get("nmap_timeout_us")),
                    content_type=fields.get("content_type"),
                    server=fields.get("server"),
                    fallback_used=_as_bool(fields.get("fallback_used")),
                    attempts=_as_int(fields.get("attempts")),
                )
            )

    return observations


def extract_feature_values(
    observations: list[Observation], feature: str
) -> list[int | None]:
    """Extract one numeric feature while preserving exclusion accounting."""

    if feature not in FEATURES:
        raise ValueError(
            f"unknown feature {feature!r}; choose one of {', '.join(FEATURES)}"
        )

    values: list[int | None] = []
    for observation in observations:
        value = getattr(observation, feature)

        # Failed HTTP transactions do not represent application response values.
        if feature in {
            "elapsed_us",
            "total_elapsed_us",
            "content_length",
            "body_bytes",
            "raw_body_bytes",
        } and not observation.success:
            value = None

        # A truncated payload is an observed lower bound, not a complete body size.
        if feature in {"body_bytes", "raw_body_bytes"} and observation.body_truncated:
            value = None

        values.append(value)

    return values

# Design

## Goal

Benmap is an explainable anomaly-ranking layer for network reconnaissance. It
normalizes response-derived measurements from active scans and passive captures,
checks whether each population is suitable for a proposed statistical model, and
preserves enough context to identify the hosts, streams, services, or subnets that
contribute most strongly to a distribution change.

## Current components

### `nse/benmap-http.nse`

The NSE script has both a `portrule` and a `postrule`.

The portrule:

1. Selects likely HTTP services through Nmap's `shortport.http` rule.
2. Makes one controlled request with caching disabled and `Accept-Encoding:
   identity` for more comparable sizes.
3. Optionally falls back from HEAD to one bounded GET.
4. Emits a structured `benmap.http.observation.v1` table on the port.
5. Stores a compact copy in a uniquely named, mutex-protected Nmap registry entry.

The postrule:

1. Reads the completed scan's observations.
2. Separates features rather than pooling incompatible measurements.
3. Applies sample, span, and diversity gates.
4. Reports ordinary concentration measures for every non-empty feature.
5. Calculates Benford metrics only for eligible populations.

The registry exists only for the current Nmap execution. Persistence and historical
comparison belong in the external analyzer.

### Python package

The Python package has three boundaries:

- `benmap.nmap_xml`: source-specific parsing and normalization.
- `benmap.analysis`: source-independent eligibility and statistics.
- `benmap.cli`: presentation and export.

The analysis module accepts a sequence of numeric values and contains no Nmap
assumptions. Wireshark, TShark, Zeek, or NetFlow adapters can therefore reuse it.

## Observation schema

The initial NSE schema is `benmap.http.observation.v1`. Important fields include:

```text
target, hostname, port, protocol, service, tls
path, method, status, success, error
elapsed_us, total_elapsed_us
content_length
body_bytes, raw_body_bytes
body_bytes_observed, raw_body_bytes_observed, body_truncated
nmap_srtt_us, nmap_rttvar_us, nmap_timeout_us
attempts, fallback_used, redirects_followed
```

Complete and observed body lengths are separate. A truncated response is useful
telemetry, but its observed bytes are a lower bound and must not masquerade as the
full response size.

## Planned phases

### Phase 1 — Nmap HTTP MVP

- [x] Structured NSE collector
- [x] Scan-wide eligibility summary
- [x] Nmap XML parser
- [x] Dependency-free analysis CLI
- [x] Localhost NSE integration test
- [ ] Contributor ranking by host, subnet, and responder metadata
- [ ] Repeated path/probe profiles for multiple observations per endpoint
- [ ] Persistent baseline store

### Phase 2 — Wireshark Lua tap

Implement a Lua tap listener for capture-wide and selected-stream statistics. Initial
features:

- TCP conversation bytes by direction
- Flow duration
- Inter-packet time within stream
- TCP ACK RTT
- HTTP request-to-response time
- HTTP content length and reassembled body size

The tap will display cohort eligibility and provide buttons that apply filters for
contributing streams. A separate postdissector can later expose rolling-window fields
for display filters and custom columns.

### Phase 3 — Headless capture analysis

Add adapters for:

- TShark field output
- PCAP/PCAPNG through a supported parser
- Zeek `conn.log` and `http.log`
- NetFlow/IPFIX exports

All adapters produce normalized observations and never place source-specific parsing
inside the statistical core.

### Phase 4 — Environmental baselines

Store cohort summaries and raw references in SQLite. Compare the current score with
historical distributions from the same authorized environment. The primary question
becomes:

> Is this behavior different from this environment's own established behavior?

The theoretical Benford distribution remains a secondary reference.

## Non-goals

- Declaring a host malicious from a first-digit score.
- Applying Benford's law to arbitrary numeric columns.
- Replacing protocol-aware analysis or packet inspection.
- Hiding failed assumptions behind a single “anomaly” number.
- Sending unbounded application requests during reconnaissance.

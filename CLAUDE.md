# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

This repo is a fork of [target/strelka](https://github.com/target/strelka), a real-time, container-based file
scanning system used for threat hunting, threat detection, and incident response. Strelka extracts files
recursively (archives, documents, email, etc.), "tastes" each extracted file to identify its type, runs the
matching set of Python scanners against it, and emits structured JSON metadata (and IOCs) per file.

**This fork adds an email/URL analysis pipeline on top of stock Strelka**, driven by Kafka, that is not part of
upstream. Be aware of this when reading code or docs — the upstream Strelka docs (`docs/README.md`,
`CONTRIBUTING.md`) describe the base gRPC/Redis pipeline accurately, but several core files have been modified in
ways that diverge from upstream behavior (see "Fork-specific additions" below).

## Architecture

### Pipeline (stock Strelka)
```
client (fileshot/oneshot/filestream) --gRPC--> frontend --Redis (coordinator)--> backend workers --Redis--> frontend --> response (log/report/Kafka)
```
- **`src/go/cmd/strelka-frontend`**: gRPC server (`ScanFile` RPC, `src/go/api/strelka/strelka.proto`) that accepts
  file uploads, writes file bytes into Redis (`coordinator`, keys `data:<id>`), pushes a task onto the Redis sorted
  set `tasks`, then blocks reading `event:<id>` until the backend finishes and pushes `"FIN"`. Optional `gatekeeper`
  Redis instance caches results by file SHA-256 to avoid rescanning duplicates.
- **`src/python/strelka/strelka.py`**: the Python backend core (`Backend.work()`). Pops tasks off Redis, pulls file
  bytes, "tastes" the file (libmagic MIME + YARA rules in `configs/python/backend/taste/taste.yara`) to assign
  **flavors**, matches flavors/filename/source against `backend.yaml`'s `scanners:` mapping to build an ordered
  scanner list (`Backend.match_scanners`), then runs each matched scanner (`Scanner.scan_wrapper` -> `Scanner.scan`).
  Scanners can recursively `emit_file()` child files, which get redistributed through the same flavor/scanner
  pipeline (tracked via `file.tree` / `depth`, capped by `limits.max_depth`).
- **`src/python/strelka/scanners/scan_*.py`**: one file per scanner, each a `strelka.Scanner` subclass. Only
  `scan()` (and optionally `init()`) needs to be overridden; write results to `self.event`, error flags to
  `self.flags`, extracted children via `self.emit_file(data, name=...)`, and indicators via `self.add_iocs(...)` /
  `self.process_ioc(...)`.
- **`src/go/cmd/strelka-manager`**: periodic Redis housekeeping (expires stale tasks/events).
- **`src/go/cmd/strelka-fileshot` / `strelka-oneshot` / `strelka-filestream`**: Go client apps for submitting files
  to the frontend (single file/dir, single file with blocking response printed to stdout, or a directory watched
  continuously — e.g. for network-sensor extracted files).
- **`src/go/pkg/rpc`**: response handling for the frontend (`LogResponses`, `ReportResponses`, `DiscardResponses`).
- **`src/go/pkg/tossS3`**: optional S3 upload/list/download helpers used as a redundancy path if Kafka delivery
  fails in the frontend.
- **`src/go/pkg/structs`**: shared config struct definitions (`Frontend`, `ConfKafka`, etc.) loaded from the
  `configs/go/*/*.yaml` files.

### Tasting, flavors, and scanner assignment
- `configs/python/backend/taste/taste.yara` — YARA rules whose *rule names become "yara flavors"* (e.g.
  `zip_file`, `docx_file`) alongside the libmagic MIME flavor.
- `configs/python/backend/backend.yaml` — the `scanners:` block maps each `Scan*` class name to one or more
  `positive`/`negative` match rules (flavors, filename regex, source) plus `priority` and per-scanner `options`.
  A flavor of `"*"` matches every file (used by e.g. `ScanYara`, `ScanEntropy`, `ScanHash`).
- Adding a new scanner requires: the scanner file in `src/python/strelka/scanners/`, a test in
  `src/python/strelka/tests/`, and a `backend.yaml` entry (plus possibly a `taste.yara` rule if it needs a new
  flavor). `src/python/strelka/tests_configuration/` cross-checks taste/scanner-assignment config consistency —
  update it when tastes or scanner mappings change.

### Fork-specific additions (not in upstream Strelka)
This fork wires Strelka into a larger email/URL analysis pipeline via Kafka:
- **`src/go/cmd/strelka-frontend/frontend_kafka.go`**: in addition to the standard gRPC `ScanFile` path, the
  frontend also runs `StartKafkaIngest`, a background Kafka consumer (topic `email.files` by default, see `main.go`)
  that decodes base64 file payloads and injects them into the same Redis `tasks`/`data:`/`event:` flow as gRPC
  requests, keyed by request `meta` (notably `mid`, a message ID used to correlate multiple artifacts from one
  email). Requires `librdkafka` — the frontend Dockerfile builds with `CGO_ENABLED=1 -tags musl` for this reason
  (other Go binaries in this repo build with `CGO_ENABLED=0`).
- **`Backend.aggregate_and_publish`** (`src/python/strelka/strelka.py`): after each file/URL artifact finishes
  scanning, results are accumulated in Redis under `agg:email:<mid>` until `expected_items` artifacts for that
  message have been processed, then a single combined JSON payload (mapping each original file/URL back to its
  analysis) is published to Kafka topic `email.files.analysis`. This is custom aggregation logic layered on top of
  stock Strelka's per-file `distribute()`/event flow — read `aggregate_and_publish` and its `_map_*`/`_build_final_payload`
  helpers together to understand how per-artifact events get reassembled into one per-email result.
- **`src/python/strelka/scanners/httpx_scanner.py`**: a custom scanner (not upstream) that treats input as a text
  file containing a URL, shells out to the `httpx` CLI to probe it (with screenshotting), reads httpx's JSONL output,
  and emits the downloaded body/screenshot as child files while also publishing them directly to Kafka topic
  `downloaded.files` for a separate downstream pipeline. Comments in this file are written in Arabic.
- **`configs/python/backend/yara/rule_updater.py`** (also duplicated at `build/python/rule_updater/rule_updater.py`,
  with its own `Dockerfile`): a standalone Kafka consumer (topic `rules_topic`) that lets an external system
  create/update/delete individual YARA rules at runtime — it patches `/etc/strelka/all_in_one.yar`, recompiles it,
  and atomically replaces `/etc/strelka/rules.compiled` (the file `ScanYara` loads per `backend.yaml`'s
  `options.compiled`). **Note:** this service is not currently wired into `build/docker-compose.yaml`, and the
  backend's `/etc/strelka` mount is read-only there — the rule_updater's compiled-rules volume must be shared with
  the backend containers for this to actually take effect.
- Root-level one-off scripts (not part of the Strelka package, used for managing the YARA rule corpus):
  `merge.py` merges/validates individual `.yar` files under a directory (e.g. `yaraify-rules/`, a large collection
  of community YARA rules) into a single `all_in_one.yar`; `compile_test.py` bulk-validates/deletes broken rules
  under a directory; `test.py` sanity-compiles `/root/discover/strelka/all_in_one.yar`; `test_to_send_rule.py`
  publishes a single `CREATE|UPDATE|UPSERT|DELETE` event for one rule file to `rules_topic` (for testing
  `rule_updater.py`). `rules/` at repo root is currently empty; `all_in_one.yar` at repo root and
  `configs/python/backend/yara/rules/all_in_one_marged.yar` are generated/merged rule bundles, not hand-written.
- Hardcoded values to watch for: several fork files (`httpx_scanner.py`, `strelka.py`'s `aggregate_and_publish`,
  `build/docker-compose.yaml`, `build/go/frontend/Dockerfile`) hardcode a specific Kafka bootstrap address
  (`38.242.221.32:9092`) and topic names rather than reading them from `backend.yaml`/`frontend.yaml` — check for
  this pattern before assuming config-file changes alone will redirect Kafka traffic.

## Common commands

### Build & run the full stack (Docker)
```sh
# build images from source
docker compose -f build/docker-compose.yaml build
docker compose -f build/docker-compose.yaml up -d

# or pull precompiled images (skip local build)
docker compose -f build/docker-compose-no-build.yaml up -d
```
The compose file expects an external Docker network (`discover_engine_pipeline_net` — replace with your actual
network name via `docker network ls`) and points several components at a live Kafka broker; a local run without a
reachable broker will need `KAFKA_BOOTSTRAP`/`kafka_bootstrap` overridden and the hardcoded addresses above patched.

### Go client apps
```sh
go build github.com/target/strelka/src/go/cmd/strelka-oneshot     # single-file, blocks for result
go build github.com/target/strelka/src/go/cmd/strelka-fileshot    # submit file(s)/directory
go build github.com/target/strelka/src/go/cmd/strelka-filestream  # watch a directory continuously
```
Building `strelka-frontend` locally (outside Docker) requires `librdkafka` headers installed (`CGO_ENABLED=1`); the
other Go binaries build with `CGO_ENABLED=0` and have no such dependency.

### Python backend tests
Most scanners have OS-level dependencies (exiftool, zeek, suricata, 7z, upx, ssdeep, etc.), so tests are run inside
the backend Docker build rather than a bare local venv:
```sh
# full scanner test suite
docker compose -f build/docker-compose.yaml build --build-arg SCANNER_TESTS=true backend

# a single scanner test file
docker compose -f build/docker-compose.yaml build --build-arg SCANNER_TESTS=true --build-arg SCANNER_TEST=test_scan_url.py backend

# configuration consistency tests (taste.yara <-> backend.yaml scanner assignment)
docker compose -f build/docker-compose.yaml build --build-arg CONFIG_TESTS=true backend
```
Tests live in `src/python/strelka/tests/` (one `test_scan_*.py`/`test_*.py` per scanner, using the
`run_test_scan` helper from `strelka.tests` and fixtures in `src/python/strelka/tests/fixtures/`) and
`src/python/strelka/tests_configuration/` (validates `taste.yara`/`backend.yaml` consistency, not individual
scanner logic).

### Linting / formatting (Python)
Enforced via pre-commit and CI; conformance is required for PRs to merge:
```sh
pre-commit install     # one-time
pre-commit run --all-files
```
Uses `black`, `isort --profile black`, and `flake8` (max line length 88, see `.flake8`).

## Style notes (from CONTRIBUTING.md, apply to scanner code)
- Write event data in `snake_case`; write it as early as possible during a scan.
- Emit known timestamps as ISO 8601 (up to seconds).
- Prefer reading file data as bytes, then `BytesIO`, then a `tempfile.NamedTemporaryFile` only if a library needs
  a real file path.
- Wrap risky operations in `try`/`except` and record failures as lower_case/underscore flags
  (`self.flags.append(f"value_error_{object_id}")`); if you catch a bare `Exception`, re-raise
  `strelka.ScannerTimeout` first so scanner timeouts aren't swallowed.
- If a scanner can extract multiple files, track counts in a `self.event["total"]` dict.
- Don't alter child file content beyond what's needed at scan time; prefer literal child filenames over
  synthesized ones when available.
- When a parent scanner adds metadata to a child file it creates, prefix the key with
  `<parent_scanner>_<field>` (e.g. `scan_rar_host_os`).
- Avoid unbounded/dynamic JSON keys — use a list of contextual dict entries instead
  (`{"segment": "foo", "sections": "bar"}` rather than `{"foo": "bar"}`).

import glob
import importlib
import itertools
import json
import base64
import logging
import math
import os
import re
import signal
import string
import time
import traceback
import uuid
from types import FrameType
from typing import Generator, Optional, Tuple
from urllib.parse import urlparse
import requests
import inflection
import magic
import redis
import validators
import yara
from boltons import iterutils
from opentelemetry import context, trace
from tldextract import TLDExtract

from . import __namespace__
from .telemetry.traces import get_tracer

from kafka import KafkaProducer
import json

perf_log = logging.getLogger("strelka.perf")



class RequestTimeout(Exception):
    """Raised when request times out."""

    def __init__(self, message="Exception: Request timeout"):
        # Call the base class constructor with the custom message
        super().__init__(message)


class DistributionTimeout(Exception):
    """Raised when file distribution times out."""

    def __init__(self, message="Exception: Distribution timeout"):
        # Call the base class constructor with the custom message
        super().__init__(message)


class ScannerTimeout(Exception):
    """Raised when scanner times out."""

    def __init__(self, message="Exception: Scanner timeout"):
        # Call the base class constructor with the custom message
        super().__init__(message)


class ScannerException(Exception):
    def __init__(self, message="Exception: Generic scanner"):
        self.message = message
        super().__init__(self.message)


class File(object):
    """Defines a file that will be scanned.

    This object contains metadata that describes files input into the
    system. The object should only contain data is that is not stored
    elsewhere (e.g. file bytes stored in Redis). In future releases this
    object may be removed in favor of a pure-Redis design.

    Attributes:
        data: Byte string of file data for local-only use
        depth: Integer that represents how deep the file was embedded.
        flavors: Dictionary of flavors assigned to the file during distribution.
        name: String that contains the name of the file.
        parent: UUIDv4 of the file that produced this file.
        pointer: String that contains the location of the file bytes in Redis.
        size: Integer of data length
        source: String that describes which scanner the file originated from.
        tree: Dictionary of relationships between File objects
        uid: String that contains a universally unique identifier (UUIDv4) used to uniquely identify the file.
    """

    # FIXME: There doesn't appear to be any reason why pointer and uid should be different
    def __init__(
        self,
        pointer: str = "",
        parent: str = "",
        depth: int = 0,
        name: str = "",
        source: str = "",
        data: Optional[bytes] = None,
    ) -> None:
        """Inits file object."""
        self.data: Optional[bytes] = data
        self.depth: int = depth
        self.flavors: dict[str, list[str]] = {}
        self.name: str = name
        self.parent: str = parent
        self.pointer: str = pointer
        self.scanners: list[str] = []
        self.size: int = -1
        self.source: str = source
        self.tree: dict = {}
        self.uid = str(uuid.uuid4())

        if not self.pointer:
            self.pointer = self.uid

    def dictionary(self) -> dict:
        return {
            "depth": self.depth,
            "flavors": self.flavors,
            "name": self.name,
            "scanners": self.scanners,
            "size": self.size,
            "source": self.source,
            "tree": self.tree,
        }

    def add_flavors(self, flavors: dict) -> None:
        """Adds flavors to the file.

        In cases where flavors and self.flavors share duplicate keys, flavors
        will overwrite the duplicate value.
        """
        self.flavors.update(flavors)


def timeout_handler(ex):
    """Signal timeout handler"""

    def fn(signal_number: int, frame: Optional[FrameType]):
        raise ex

    return fn


class Backend(object):
    def __init__(
        self,
        backend_cfg: dict,
        coordinator: Optional[redis.StrictRedis] = None,
        disable_coordinator: Optional[bool] = False,
    ) -> None:
        self.scanner_cache: dict = {}
        self.backend_cfg: dict = backend_cfg
        self.coordinator: Optional[redis.StrictRedis] = None
        self.limits: dict = backend_cfg.get("limits", {})
        self.scanners: dict = backend_cfg.get("scanners", {})
        self.blocking_pop_time_sec: int = backend_cfg.get("coordinator", {}).get(
            "blocking_pop_time_sec", 0
        )

        self.tracer = get_tracer(
            backend_cfg.get("telemetry", {}).get("traces", {}),
            meta={
                "strelka.config.version": self.backend_cfg.get("version", ""),
                "strelka.config.sha1": self.backend_cfg.get("sha1", ""),
            },
        )

        self.compiled_magic = magic.Magic(
            magic_file=backend_cfg.get("tasting", {}).get("mime_db", None),
            mime=True,
        )

        yara_rules = backend_cfg.get("tasting", {}).get(
            "yara_rules", "/etc/strelka/taste/"
        )
        if os.path.isdir(yara_rules):
            yara_filepaths = {}
            globbed_yara = glob.iglob(
                f"{yara_rules}/**/*.yar*",
                recursive=True,
            )
            for i, entry in enumerate(globbed_yara):
                yara_filepaths[f"namespace{i}"] = entry
            self.compiled_taste_yara = yara.compile(filepaths=yara_filepaths)
        else:
            self.compiled_taste_yara = yara.compile(filepath=yara_rules)

        # If a coordinator is supplied, use it unless explicitly disabled
        if coordinator and disable_coordinator is False:
            self.coordinator = coordinator
            if self.coordinator.ping():
                logging.debug("coordinator up")
            else:
                raise Exception("coordinator ping failed")

        #  If a coordinator is not supplied, try to make one from the config file
        #  unless explicitly disabled
        elif (
            not coordinator
            and disable_coordinator is False
            and backend_cfg.get("coordinator")
        ):
            try:
                coordinator_cfg = backend_cfg.get("coordinator")
                coordinator_addr = coordinator_cfg.get("addr").split(":")
                self.coordinator = redis.StrictRedis(
                    host=coordinator_addr[0],
                    port=coordinator_addr[1],
                    db=coordinator_cfg.get("db"),
                )
                if self.coordinator.ping():
                    logging.debug("coordinator up")
                else:
                    raise Exception("coordinator ping failed")
            except Exception:
                logging.exception("coordinator unavailable")
                raise

        if not self.coordinator:
            logging.info("backend started without coordinator")

        self._kafka_producer: Optional[KafkaProducer] = None
        self._kafka_bootstrap = "kafka:29092"

        self.fan_out_children: bool = bool(
            backend_cfg.get("processing", {}).get("fan_out_children", False)
        )

        import socket
        self.worker_id: str = os.environ.get("HOSTNAME") or socket.gethostname()
        self.worker_pid: int = os.getpid()

        self.STAGES = (
            "ingest",
            "distribute",
            "file_analysis",
            "url_analysis",
            "aggregation",
            "finalize",
            "publish",
        )

        self._url_scanners = frozenset({"HttpxScanner", "ScanUrl"})

        trace_cfg = backend_cfg.get("trace", {}) or {}
        self._heavy_file_bytes: int = int(
            trace_cfg.get("heavy_file_size_bytes", 5 * 1024 * 1024)
        )
        self._heavy_file_share: float = float(
            trace_cfg.get("heavy_file_share_threshold", 0.30)
        )

        self._pretty_trace_log: bool = bool(
            trace_cfg.get("pretty_log", True)
        )

        self._trace_format: str = str(trace_cfg.get("format", "simple")).lower()

        self._suppress_stage_events: bool = bool(
            trace_cfg.get("suppress_stage_events", False)
        )

    def _get_kafka_producer(self) -> KafkaProducer:
        if self._kafka_producer is None:

            self._kafka_producer = KafkaProducer(
                bootstrap_servers=self._kafka_bootstrap,
                value_serializer=lambda x: json.dumps(x).encode("utf-8"),
                max_request_size=104857600,
                linger_ms=20,
                acks=1,
                compression_type="gzip",
            )
        return self._kafka_producer

    def _perf(self, payload: dict) -> None:
        """Emit one JSON line on the strelka.perf logger. Always stamps the
        worker identity and a wall-clock ISO-8601 timestamp so a stream of
        records from many containers can be merged and ordered downstream.
        Callers may pre-populate any of these fields to override.
        """
        try:
            payload.setdefault("worker", self.worker_id)
            payload.setdefault("worker_pid", self.worker_pid)
            payload.setdefault(
                "timestamp",
                time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) +
                f".{int((time.time() % 1) * 1000):03d}Z",
            )
            perf_log.info(json.dumps(payload, default=str))
        except Exception:
            pass

    def _stage_event(
        self,
        mid: str,
        trace_id: str,
        stage: str,
        event: str,
        duration_ms: Optional[float] = None,
        total_duration_ms: Optional[float] = None,
        **fields,
    ) -> None:
        """Emit a stage start/end record in the canonical schema.
        {mid, trace_id, stage, event, worker, timestamp, duration_ms, ...}
        Extra fields (filename, root_id, depth, scanners, n_files, etc.) are
        merged in. When trace.suppress_stage_events is true (high-throughput
        mode), these per-stage records are silently dropped; the single
        email_summary at finalize still carries all aggregated durations.
        """
        if self._suppress_stage_events:
            return
        payload = {
            "evt": "stage",
            "mid": mid,
            "trace_id": trace_id,
            "stage": stage,
            "event": event,
        }
        if duration_ms is not None:
            payload["duration_ms"] = round(float(duration_ms), 3)
        if total_duration_ms is not None:
            payload["total_duration_ms"] = round(float(total_duration_ms), 3)
        payload.update(fields)
        self._perf(payload)

    def _stage_record(
        self,
        root_id: str,
        stage: str,
        duration_ms: float,
        expire_at: Optional[int] = None,
    ) -> None:
        """Add `duration_ms` to the per-artifact stage total in Redis. Used by
        every worker that contributes to an artifact so the finalizer can read
        the totals back at email_summary emission time.
        """
        if not self.coordinator or stage not in self.STAGES:
            return
        try:
            p = self.coordinator.pipeline(transaction=False)
            p.hincrbyfloat(f"art:{root_id}:stages", stage, float(duration_ms))
            p.sadd(f"art:{root_id}:workers", self.worker_id)
            if expire_at is not None:
                p.expireat(f"art:{root_id}:stages", expire_at)
                p.expireat(f"art:{root_id}:workers", expire_at)
            p.execute()
        except Exception:
            # Never let perf bookkeeping block real work.
            pass

    @staticmethod
    def _human_size(n: int) -> str:
        n = float(max(0, int(n)))
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024.0:
                return f"{n:.2f} {unit}" if unit != "B" else f"{int(n)} B"
            n /= 1024.0
        return f"{n:.2f} PB"

    def _file_metadata_from_events(self, events: list) -> tuple:
        """Walk the events list (one entry per scanned file at any depth) and
        produce the per-file metadata array used by the email_summary.
        Returns (files_list, totals_dict). Pure function; never raises.
        """
        files_meta: list = []
        total_size_bytes = 0
        total_file_analysis_ms = 0.0
        for e in events or []:
            f = (e.get("file") or {})
            size = int(f.get("size") or 0)
            scanner_timings = f.get("_scanner_timings") or []
            analysis_ms = 0.0
            for st in scanner_timings:
                try:
                    analysis_ms += float(st.get("ms") or 0.0)
                except (TypeError, ValueError):
                    pass
            flavors = f.get("flavors") or {}
            mime_list = flavors.get("mime") or []
            mime = mime_list[0] if isinstance(mime_list, list) and mime_list else ""
            files_meta.append({
                "name": f.get("name") or "",
                "uid": f.get("uid") or "",
                "depth": int(f.get("depth") or 0),
                "size_bytes": size,
                "size_human": self._human_size(size),
                "mime": mime,
                "analysis_time_ms": round(analysis_ms, 3),
                "ms_per_kb": round(
                    (analysis_ms / (size / 1024.0)) if size > 0 else 0.0, 3
                ),
                "scanners": [
                    {"scanner": st.get("scanner"),
                     "ms": round(float(st.get("ms") or 0.0), 3)}
                    for st in scanner_timings
                ],
            })
            total_size_bytes += size
            total_file_analysis_ms += analysis_ms

        totals = {
            "total_files": len(files_meta),
            "total_size_bytes": total_size_bytes,
            "total_size_human": self._human_size(total_size_bytes),
            "total_file_analysis_ms": round(total_file_analysis_ms, 3),
        }
        return files_meta, totals

    def _heavy_file_flags(self, files_meta: list, total_file_analysis_ms: float) -> list:
        """Return list of {name, reason, size_human, share_of_analysis} for any
        file that satisfies size>threshold AND share of analysis > threshold.
        """
        flagged: list = []
        if total_file_analysis_ms <= 0:
            return flagged
        for f in files_meta:
            if f["size_bytes"] < self._heavy_file_bytes:
                continue
            share = f["analysis_time_ms"] / total_file_analysis_ms
            if share >= self._heavy_file_share:
                flagged.append({
                    "name": f["name"],
                    "size_human": f["size_human"],
                    "analysis_time_ms": f["analysis_time_ms"],
                    "share_of_analysis": round(share, 3),
                    "reason": "heavy_file_bottleneck",
                })
        return flagged

    def _render_simple_trace_block(self, summary: dict) -> str:
        """Single canonical per-email trace block. Aggregates the per-stage
        totals collected in Redis into the operator-facing 5-stage view:

            queue_wait, distribute, file_analysis, aggregation, publish

        Emitted exactly once per email (the finalizer is single-instance by
        construction -- the artifact pending counter goes to 0 in exactly
        one worker). Thread/distributed safe.
        """
        stages = summary.get("stages", {}) or {}
        mid = summary.get("mid", "")
        total_ms = summary.get("total_processing_time_ms", 0)
        queue_wait = stages.get("ingest", 0) or 0
        distribute = stages.get("distribute", 0) or 0
        file_analysis = (stages.get("file_analysis", 0) or 0) + (
            stages.get("url_analysis", 0) or 0
        )
        aggregation = (stages.get("aggregation", 0) or 0) + (
            stages.get("finalize", 0) or 0
        )
        publish = stages.get("publish", 0) or 0

        def fmt(v) -> str:
            return f"{int(round(float(v)))}"

        return (
            f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"EMAIL TRACE: {mid}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"queue_wait        → {fmt(queue_wait)} ms\n"
            f"distribute        → {fmt(distribute)} ms\n"
            f"file_analysis     → {fmt(file_analysis)} ms\n"
            f"aggregation       → {fmt(aggregation)} ms\n"
            f"publish           → {fmt(publish)} ms\n\n"
            f"--------------------------------\n"
            f"TOTAL TIME        → {fmt(total_ms)} ms\n"
            f"--------------------------------\n"
        )

    def _render_email_trace_block(self, summary: dict) -> str:
        """Build the human-readable EMAIL TRACE block requested by ops.
        Returns the formatted string; the caller prints to stdout.
        """
        mid = summary.get("mid", "")
        stages = summary.get("stages", {}) or {}
        bottleneck = summary.get("bottleneck_stage", "")
        files = summary.get("files", [])
        total_files = summary.get("total_files", 0)
        total_size_human = summary.get("total_size_human", "0 B")
        workers = summary.get("workers", []) or []
        status = summary.get("status", "SUCCESS")
        total_ms = summary.get("total_processing_time_ms", 0)
        heavy = summary.get("heavy_file_bottlenecks") or []
        ms_per_kb_avg = summary.get("ms_per_kb_avg")
        top_slow = summary.get("top_slowest_files") or []

        # Format stages with a 🔥 marker on the bottleneck.
        stage_lines = []
        for s in self.STAGES:
            val = stages.get(s, 0)
            marker = "  🔥 bottleneck" if s == bottleneck else ""
            stage_lines.append(f"{s:<17} → {int(round(val))} ms{marker}")

        file_lines = []
        for i, f in enumerate(files, 1):
            file_lines.append(
                f"file_{i}:\n"
                f"   name           → {f.get('name') or '(unnamed)'}\n"
                f"   size           → {f.get('size_human')}\n"
                f"   mime           → {f.get('mime') or '(unknown)'}\n"
                f"   analysis_time  → {int(round(f.get('analysis_time_ms') or 0))} ms"
            )

        heavy_lines = ""
        if heavy:
            heavy_lines = "\n--------------------------------\nHEAVY FILE BOTTLENECKS\n--------------------------------\n"
            for h in heavy:
                heavy_lines += (
                    f"  ⚠️  {h.get('name')} "
                    f"({h.get('size_human')}, "
                    f"{int(round(h.get('analysis_time_ms') or 0))} ms, "
                    f"{int(round((h.get('share_of_analysis') or 0) * 100))}% of analysis)\n"
                )

        top_slow_lines = ""
        if top_slow:
            top_slow_lines = "\n--------------------------------\nTOP 3 SLOWEST FILES\n--------------------------------\n"
            for i, f in enumerate(top_slow, 1):
                top_slow_lines += (
                    f"  {i}. {f.get('name') or '(unnamed)'} "
                    f"({f.get('size_human')}, "
                    f"{int(round(f.get('analysis_time_ms') or 0))} ms)\n"
                )

        ratio_line = ""
        if ms_per_kb_avg is not None:
            ratio_line = f"AVG ms/KB         → {ms_per_kb_avg}\n"

        return (
            f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"EMAIL TRACE: {mid}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"\n" + "\n".join(stage_lines) + "\n"
            f"\n--------------------------------\n"
            f"FILES METADATA\n"
            f"--------------------------------\n"
            f"total_files       → {total_files}\n"
            f"total_size        → {total_size_human}\n"
            f"{ratio_line}"
            f"\n" + "\n\n".join(file_lines) + ("\n" if file_lines else "")
            + top_slow_lines
            + heavy_lines
            + f"\n--------------------------------\n"
            f"TOTAL TIME        → {int(round(total_ms))} ms\n"
            f"WORKERS           → {workers}\n"
            f"STATUS            → {status}\n"
            f"--------------------------------\n"
        )

    def _trace_id_from(self, request_meta: dict, root_id: str) -> str:
        """Pick a trace id: explicit meta.trace_id > w3c traceparent > root_id."""
        if not request_meta:
            return root_id
        explicit = request_meta.get("trace_id")
        if explicit:
            return str(explicit)
        tp = request_meta.get("traceparent") or request_meta.get("tracecontext")
        if tp:
            # traceparent = "version-traceid-spanid-flags"
            parts = str(tp).split("-")
            if len(parts) >= 2 and parts[1]:
                return parts[1]
        return root_id

    def taste_mime(self, data: bytes) -> list:
        """Tastes file data with libmagic."""
        return [self.compiled_magic.from_buffer(data)]

    def taste_yara(self, data: bytes) -> list:
        """Tastes file data with YARA."""

        taste_yara_matches = self.compiled_taste_yara.match(data=data)

        return [match.rule for match in taste_yara_matches]

    def transform_leading_whitespace(self, data):
        encoded_whitespace = string.whitespace.encode()
        return data.lstrip(encoded_whitespace)

    def match_flavors(self, data: bytes) -> dict:
        mimes = []
        yaras = []

        mimes.extend(self.taste_mime(data))
        yaras.extend(self.taste_yara(data))

        # Taste transformations (yara only)
        if data:
            try:
                # Remove leading whitespace
                if data[0] in string.whitespace.encode():
                    # mimes.extend(self.taste_mime(self.transform_leading_whitespace(data)))
                    yaras.extend(
                        self.taste_yara(self.transform_leading_whitespace(data))
                    )
            except Exception:
                logging.exception("file transformation failed")

        return {"mime": list(set(mimes)), "yara": list(set(yaras))}

    def check_scanners(self):
        """attempt to import all scanners referenced in the backend configuration"""
        logging.info("checking scanners")
        if self.scanners:
            for name in self.scanners:
                try:
                    und_name = inflection.underscore(name)
                    scanner_import = f"strelka.scanners.{und_name}"
                    importlib.import_module(scanner_import)
                except ModuleNotFoundError:
                    raise

    def work(self) -> None:
        """Process tasks from Redis coordinator"""

        logging.info("starting up")

        if not self.coordinator:
            logging.error("no coordinator specified")
            return

        self.check_scanners()

        count = 0
        work_start = time.time()
        work_expire = work_start + self.limits.get("time_to_live", 900)

        while True:
            if self.limits.get("max_files") != 0:
                if count >= self.limits.get("max_files", 5000):
                    break
            if self.limits.get("time_to_live") != 0:
                if time.time() >= work_expire:
                    break

            # Retrieve request task from Redis coordinator
            if self.blocking_pop_time_sec > 0:
                task = self.coordinator.bzpopmin(
                    "tasks", timeout=self.blocking_pop_time_sec
                )
                if task is None:
                    continue

                (queue_name, task_item, expire_at) = task
            else:
                task = self.coordinator.zpopmin("tasks", count=1)
                if len(task) == 0:
                    time.sleep(0.25)
                    continue

                # Get request metadata and Redis context deadline UNIX timestamp
                (task_item, expire_at) = task[0]

            traceparent = None
            task_info = {}
            request_meta = {}
            is_child_task = False
            self_id = ""

            # Support old (ID only) and new (JSON) style requests
            try:
                task_info = json.loads(task_item)
            except json.JSONDecodeError:
                root_id = task_item.decode()
                self_id = root_id
                # Create new file object for task, use the request root_id as the pointer
                file = File(pointer=root_id)
            else:
                self_id = task_info.get("id", "")
                task_root = task_info.get("root") or self_id
                root_id = task_root
                is_child_task = bool(task_info.get("root")) and task_info["root"] != self_id
                request_meta = task_info.get("meta", {}) or {}
                try:
                    file = File(
                        pointer=self_id, name=task_info["attributes"]["filename"]
                    )
                    traceparent = task_info.get("tracecontext", "")
                except KeyError as ex:
                    logging.debug(
                        f"No filename attached (error: {ex}) to request: {task_item}"
                    )
                    file = File(pointer=self_id)

                file.parent = task_info.get("parent", "") or ""
                try:
                    file.depth = int(task_info.get("depth", 0) or 0)
                except (TypeError, ValueError):
                    file.depth = 0

            expire_at = math.ceil(expire_at)
            timeout = math.ceil(expire_at - time.time())

            # If the deadline has passed, bail out
            if timeout <= 0:
                continue

            mid_for_perf = (request_meta or {}).get("mid") or root_id
            trace_id = self._trace_id_from(request_meta, root_id)
            enqueued_at = (request_meta or {}).get("enqueued_at")
            try:
                queue_wait_ms = (
                    (time.time() - float(enqueued_at)) * 1000.0
                    if enqueued_at is not None
                    else None
                )
            except (TypeError, ValueError):
                queue_wait_ms = None

            self._stage_event(
                mid_for_perf, trace_id, "ingest", "start",
                root_id=root_id, depth=file.depth,
                is_child=is_child_task, queue_wait_ms=queue_wait_ms,
                filename=file.name or "",
            )
            ingest_ms = queue_wait_ms if queue_wait_ms is not None else 0.0
            self._stage_event(
                mid_for_perf, trace_id, "ingest", "end",
                duration_ms=ingest_ms, root_id=root_id, depth=file.depth,
                filename=file.name or "",
            )

            stage_timings: dict = {}
            events: list = []
            email_t_start = time.monotonic()
            email_result = "ok"

            try:
                # Prepare timeout handler
                signal.signal(signal.SIGALRM, timeout_handler(RequestTimeout))
                signal.alarm(timeout)

                if self.fan_out_children and not is_child_task and self.coordinator:
                    ttl_sec = max(int(expire_at - time.time()), 1)
                    meta_blob = json.dumps({
                        "request_meta": request_meta,
                        "root_id": root_id,
                        "root_file_name": file.name or "",
                        "root_enqueued_at": enqueued_at,
                        "trace_id": trace_id,
                        "mid": mid_for_perf,
                    })
                    init_p = self.coordinator.pipeline(transaction=False)
                    init_p.hsetnx(f"art:{root_id}:counters", "pending", 1)
                    init_p.expire(f"art:{root_id}:counters", ttl_sec)
                    init_p.set(f"art:{root_id}:meta", meta_blob, ex=ttl_sec, nx=True)
                    init_p.execute()

                # ── stage: file_analysis ─────────────────────────────────
                self._stage_event(
                    mid_for_perf, trace_id, "file_analysis", "start",
                    root_id=root_id, depth=file.depth,
                    filename=file.name or "",
                )
                t0 = time.monotonic()
                events = self.distribute(
                    root_id,
                    file,
                    expire_at,
                    traceparent=traceparent,
                    request_meta=request_meta,
                    stage_timings=stage_timings,
                )
                file_analysis_ms = (time.monotonic() - t0) * 1000.0
                stage_timings["distribute_ms"] = file_analysis_ms

                url_analysis_ms = 0.0
                for e in events:
                    for st in (e.get("file") or {}).get("_scanner_timings", []) or []:
                        if st.get("scanner") in self._url_scanners:
                            url_analysis_ms += float(st.get("ms") or 0.0)
                file_only_ms = max(0.0, file_analysis_ms - url_analysis_ms)
                self._stage_record(root_id, "file_analysis", file_only_ms, expire_at)
                if url_analysis_ms > 0:
                    self._stage_record(root_id, "url_analysis", url_analysis_ms, expire_at)

                self._stage_record(root_id, "ingest", ingest_ms, expire_at)
                distribute_ms = (
                    float(stage_timings.get("lpop_ms") or 0.0)
                    + float(stage_timings.get("flavor_match_ms") or 0.0)
                    + float(stage_timings.get("scanner_match_ms") or 0.0)
                )
                if distribute_ms > 0:
                    self._stage_record(root_id, "distribute", distribute_ms, expire_at)
                self._stage_event(
                    mid_for_perf, trace_id, "file_analysis", "end",
                    duration_ms=file_analysis_ms,
                    root_id=root_id, depth=file.depth,
                    filename=file.name or "",
                    n_events=len(events),
                    url_ms=round(url_analysis_ms, 3),
                )

                if self.fan_out_children and self.coordinator:
                    # ── stage: aggregation ───────────────────────────────
                    self._stage_event(
                        mid_for_perf, trace_id, "aggregation", "start",
                        root_id=root_id, n_events=len(events),
                    )
                    t_agg = time.monotonic()
                    if events:
                        ev_p = self.coordinator.pipeline(transaction=False)
                        for e in events:
                            ev_p.rpush(
                                f"art:{root_id}:events",
                                json.dumps(self._json_sanitize(e)),
                            )
                        ev_p.expireat(f"art:{root_id}:events", expire_at)
                        ev_p.execute()
                    agg_ms = (time.monotonic() - t_agg) * 1000.0
                    self._stage_record(root_id, "aggregation", agg_ms, expire_at)
                    self._stage_event(
                        mid_for_perf, trace_id, "aggregation", "end",
                        duration_ms=agg_ms, root_id=root_id,
                    )

                    new_pending = int(
                        self.coordinator.hincrby(
                            f"art:{root_id}:counters", "pending", -1
                        )
                    )
                    if new_pending <= 0:
                        t0 = time.monotonic()
                        self._finalize_artifact(root_id, expire_at)
                        stage_timings["aggregate_publish_ms"] = (
                            time.monotonic() - t0
                        ) * 1000.0
                else:
                    t0 = time.monotonic()
                    self.aggregate_and_publish(
                        root_id, file, events, request_meta
                    )
                    stage_timings["aggregate_publish_ms"] = (
                        time.monotonic() - t0
                    ) * 1000.0


                    p = self.coordinator.pipeline(transaction=False)
                    p.rpush(f"event:{root_id}", "FIN")
                    p.expireat(f"event:{root_id}", expire_at)
                    p.execute()

                # Reset timeout handler
                signal.alarm(0)

            except RequestTimeout:
                email_result = "request_timeout"
                logging.debug(f"[strelka_flow] ⚠️ mid={request_meta.get('mid', root_id)} stage=aggregation action=partial reason=request_timeout status=warning")
            except Exception:
                email_result = "exception"
                signal.alarm(0)
                logging.exception(f"[strelka_flow] ❌ mid={request_meta.get('mid', root_id)} stage=analysis action=failure status=failed error=unknown_exception")

            total_ms = (time.monotonic() - email_t_start) * 1000.0
            scanners_used = sorted({
                s
                for e in events
                for s in ((e.get("file") or {}).get("scanners") or [])
            })
            self._perf({
                "evt": "email_done",
                "mid": mid_for_perf,
                "trace_id": trace_id,
                "root_id": root_id,
                "is_child": is_child_task,
                "queue_wait_ms": queue_wait_ms,
                "total_ms": total_ms,
                "n_files": len(events),
                "stages": stage_timings,
                "scanners_used": scanners_used,
                "result": email_result,
            })

            count += 1

        logging.info(
            f"shutdown after servicing {count} requests(s) and"
            f" {time.time() - work_start} second(s)"
        )

    def distribute(
        self,
        root_id: str,
        file: File,
        expire_at: int,
        traceparent: Optional[str] = "",
        request_meta: Optional[dict] = None,
        stage_timings: Optional[dict] = None,
    ) -> list[dict]:
        """Distributes a file through scanners.

        Args:
            root_id: Root request/file UUIDv4
            file: File object
            expire_at: Deadline UNIX timestamp
            traceparent: OpenTelemetry tracing context
        Returns:
            List of event dictionaries
        """

        from opentelemetry.trace.propagation.tracecontext import (
            TraceContextTextMapPropagator,
        )

        if traceparent:
            carrier = {"traceparent": traceparent}
            ctx = TraceContextTextMapPropagator().extract(carrier)
            context.attach(ctx)

        with self.tracer.start_as_current_span("distribute") as distribute_span:
            try:
                data = b""
                files = []
                events = []
                request_meta = request_meta or {}
                mid = request_meta.get("mid", root_id)

                pipeline = None

                try:
                    # Prepare timeout handler
                    signal.signal(signal.SIGALRM, timeout_handler(DistributionTimeout))
                    signal.alarm(self.limits.get("distribution", 600))

                    if file.depth > self.limits.get("max_depth", 15):
                        logging.info(f"request {root_id} exceeded maximum depth")
                        return []

                    # Distribute can work local-only (data in File) or through a coordinator
                    if file.data:
                        # Pull data for file from File object
                        data = file.data
                    elif self.coordinator:
                        # Pull data for file from coordinator
                        _t_lpop = time.monotonic()
                        with self.tracer.start_as_current_span("lpop"):
                            while True:
                                pop = self.coordinator.lpop(f"data:{file.pointer}")
                                if pop is None:
                                    break
                                data += pop
                        if stage_timings is not None:
                            stage_timings["lpop_ms"] = (time.monotonic() - _t_lpop) * 1000.0

                        # Initialize Redis pipeline
                        pipeline = self.coordinator.pipeline(transaction=False)
                    else:
                        raise Exception("No data or coordinator available")

                    # Match data to mime and yara flavors
                    _t_flavor = time.monotonic()
                    file.add_flavors(self.match_flavors(data))
                    _flavor_ms = (time.monotonic() - _t_flavor) * 1000.0

                    # Get list of matching scanners
                    _t_sm = time.monotonic()
                    scanner_list = self.match_scanners(file)
                    _scanner_match_ms = (time.monotonic() - _t_sm) * 1000.0
                    if stage_timings is not None:
                        stage_timings["flavor_match_ms"] = _flavor_ms
                        stage_timings["scanner_match_ms"] = _scanner_match_ms

                    tree_dict = {
                        "node": file.uid,
                        "parent": file.parent,
                        "root": root_id,
                    }

                    # Since root_id comes from the request, use that instead of the file's uid
                    if file.depth == 0:
                        tree_dict["node"] = root_id
                    if file.depth == 1:
                        tree_dict["parent"] = root_id

                    # Update the file object
                    file.scanners = [s.get("name") for s in scanner_list]
                    file.size = len(data)
                    file.tree = tree_dict

                    # Set span attributes for the File object
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.depth", file.depth
                    )
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.flavors.mime",
                        file.flavors.get("mime", ""),
                    )
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.flavors.yara",
                        file.flavors.get("yara", ""),
                    )
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.flavors.external",
                        file.flavors.get("external", ""),
                    )
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.name", file.name
                    )
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.pointer", file.pointer
                    )
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.scanners", file.scanners
                    )
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.size", file.size
                    )
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.source", file.source
                    )
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.tree.node", file.tree.get("node", "")
                    )
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.tree.parent", file.tree.get("parent", "")
                    )
                    distribute_span.set_attribute(
                        f"{__namespace__}.file.tree.root", file.tree.get("root", "")
                    )

                    scan: dict = {}
                    iocs: list = []
                    scanner_timings: list = []

                    for scanner in scanner_list:
                        _t_scan = time.monotonic()
                        try:
                            name = scanner["name"]
                            und_name = inflection.underscore(name)
                            scanner_import = f"strelka.scanners.{und_name}"
                            module = importlib.import_module(scanner_import)

                            if self.backend_cfg.get("caching", {"scanner": True}).get(
                                "scanner", True
                            ):
                                # Cache a copy of each scanner object
                                if und_name not in self.scanner_cache:
                                    attr = getattr(module, name)(
                                        self.backend_cfg, self.coordinator
                                    )
                                    self.scanner_cache[und_name] = attr
                                plugin = self.scanner_cache[und_name]

                                # Clear cached scanner of files
                                plugin.files = []
                                plugin.flags = []
                            else:
                                plugin = getattr(module, name)(
                                    self.backend_cfg, self.coordinator
                                )

                            options = scanner.get("options", {})

                            # Run the scanner
                            (
                                scanner_files,
                                scanner_event,
                                scanner_iocs,
                            ) = plugin.scan_wrapper(
                                data,
                                file,
                                options,
                                expire_at,
                            )

                            # Collect extracted files and iocs
                            files.extend(scanner_files)
                            iocs.extend(scanner_iocs)

                            # clear the scanner ioc list after each use
                            plugin.iocs = []

                            scan = {**scan, **scanner_event}

                        except ModuleNotFoundError:
                            logging.exception(
                                f'scanner {scanner.get("name", "__missing__")} not'
                                " found"
                            )
                        finally:
                            scanner_timings.append({
                                "scanner": scanner.get("name", "__missing__"),
                                "ms": (time.monotonic() - _t_scan) * 1000.0,
                            })

                    file_dict = file.dictionary()
                    file_dict["_scanner_timings"] = scanner_timings
                    event = {
                        "file": file_dict,
                        "scan": scan,
                        "iocs": iocs,
                    }

                    # Collect events for local-only
                    events.append(event)
                    file_name = file.name or ""
                    if "___urls___" in file_name:
                        logging.info(
                            f"[strelka_flow] 🔗 mid={mid} stage=url_analysis action=start url={request_meta.get('artifact_name', file_name)} status=running"
                        )
                    elif file_name.endswith(".zip") or file_name.endswith(".rar") or file_name.endswith(".7z") or file_name.endswith(".tar") or file_name.endswith(".gz"):
                        logging.info(
                            f"[strelka_flow] 📦 mid={mid} stage=archive_analysis action=start filename={file_name} status=running"
                        )
                    elif file.depth > 0:
                        logging.info(
                            f"[strelka_flow] 🧩 mid={mid} stage=archive_child action=analyzed filename={file_name} status=success"
                        )
                    else:
                        logging.info(
                            f"[strelka_flow] 📄 mid={mid} stage=file_analysis action=start filename={file_name or request_meta.get('artifact_name', 'unknown')} status=running"
                        )

                    # Send event back to Redis coordinator
                    if pipeline:
                        pipeline.rpush(f"event:{root_id}", format_event(event))
                        pipeline.expireat(f"event:{root_id}", expire_at)
                        pipeline.execute()
                    signal.alarm(0)

                    self._perf({
                        "evt": "file_done",
                        "mid": mid,
                        "trace_id": self._trace_id_from(request_meta or {}, root_id),
                        "root_id": root_id,
                        "file_uid": file.uid,
                        "parent": file.parent,
                        "depth": file.depth,
                        "name": file.name,
                        "size": file.size,
                        "flavors": file.flavors,
                        "scanners": scanner_timings,
                        "n_children_extracted": len(files),
                    })

                except DistributionTimeout:
                    # FIXME: node id is not always file.uid
                    logging.exception(f"node {file.uid} timed out")

                if (
                    self.fan_out_children
                    and self.coordinator
                    and files
                ):
                    child_count = len(files)
                    mid_for_children = (request_meta or {}).get("mid", "")
                    fanout_p = self.coordinator.pipeline(transaction=True)
                    fanout_p.hincrby(
                        f"art:{root_id}:counters", "pending", child_count
                    )
                    for scanner_file in files:
                        scanner_file.parent = file.uid
                        scanner_file.depth = file.depth + 1
                        child_task = {
                            "id": scanner_file.pointer,
                            "root": root_id,
                            "parent": file.uid,
                            "depth": file.depth + 1,
                            "attributes": {
                                "filename": scanner_file.name or "",
                            },
                            "source": scanner_file.source or "",
                            "meta": {
                                "mid": mid_for_children,
                                "trace_id": self._trace_id_from(
                                    request_meta or {}, root_id
                                ),
                                "_child": True,
                            },
                        }
                        fanout_p.zadd(
                            "tasks",
                            {json.dumps(child_task): float(expire_at)},
                        )
                        fanout_p.expireat(
                            f"data:{scanner_file.pointer}", expire_at
                        )
                    fanout_p.execute()
                    self._perf({
                        "evt": "fanout",
                        "root_id": root_id,
                        "parent_uid": file.uid,
                        "parent_depth": file.depth,
                        "n_children": child_count,
                    })
                elif files:

                    for scanner_file in files:
                        scanner_file.parent = file.uid
                        scanner_file.depth = file.depth + 1
                        events.extend(
                            self.distribute(
                                root_id,
                                scanner_file,
                                expire_at,
                                request_meta=request_meta,
                            )
                        )

            except RequestTimeout:
                signal.alarm(0)
                raise

            return events

    def aggregate_and_publish(self, root_id: str, root_file: File, events: list[dict], request_meta: Optional[dict] = None) -> None:
        request_meta = request_meta or {}
        mid = str(request_meta.get("mid") or root_id)
        expected_items = self._safe_int(request_meta.get("expected_items"), 1)
        artifact_type = request_meta.get("artifact_type") or self._derive_request_type(root_file.name)
        artifact_name = request_meta.get("artifact_name") or root_file.name

        logging.info(f"[strelka_flow] 📥 mid={mid} stage=ingest action=received_full_email status=ok")
        logging.info(f"[strelka_flow] 🔄 mid={mid} stage=aggregation action=start status=running")

        email_context = self._decode_email_context(mid, request_meta.get("email_context_b64", ""))
        artifact_payload = {
            "root_id": root_id,
            "artifact_type": artifact_type,
            "artifact_name": artifact_name,
            "artifact_index": self._safe_int(request_meta.get("artifact_index"), 0),
            "root_file": root_file.dictionary(),
            "events": events,
            "archive_children": [
                e for e in events if ((e.get("file") or {}).get("tree") or {}).get("parent") not in ("", root_id, None)
            ],
            "counts": {
                "total_events": len(events),
                "archive_children": len(
                    [e for e in events if ((e.get("file") or {}).get("tree") or {}).get("parent") not in ("", root_id, None)]
                ),
            },
        }

        agg_key = f"agg:email:{mid}"
        items_key = f"{agg_key}:items"
        publish_lock_key = f"{agg_key}:published"
        ttl_seconds = self.limits.get("time_to_live", 900)

        p = self.coordinator.pipeline(transaction=False)
        p.hsetnx(agg_key, "mid", mid)
        p.hsetnx(agg_key, "expected_items", expected_items)
        if email_context:
            p.hsetnx(agg_key, "email_context", json.dumps(email_context))
        p.rpush(items_key, json.dumps(self._json_sanitize(artifact_payload)))
        p.hincrby(agg_key, "processed_items", 1)
        p.expire(agg_key, ttl_seconds)
        p.expire(items_key, ttl_seconds)
        result = p.execute()
        processed = int(result[4] if len(result) > 4 else 0)
        expected = int(self.coordinator.hget(agg_key, "expected_items") or expected_items)

        logging.info(
            f"[strelka_flow] 🔄 mid={mid} stage=aggregation action=merged processed={processed} expected={expected} status=running"
        )

        if processed < expected:
            return

        lock_ok = self.coordinator.set(publish_lock_key, "1", nx=True, ex=ttl_seconds)
        if not lock_ok:
            return

        raw_items = self.coordinator.lrange(items_key, 0, -1) or []
        artifact_items = []
        for raw_item in raw_items:
            try:
                artifact_items.append(json.loads(raw_item))
            except Exception:
                continue

        payload = self._build_final_payload(mid, email_context, artifact_items, expected, processed)
        topic = "email.files.analysis"
        _t_kafka = time.monotonic()
        producer = self._get_kafka_producer()
        producer.send(topic, value=self._json_sanitize(payload))
        producer.flush(timeout=5)
        kafka_ms = (time.monotonic() - _t_kafka) * 1000.0
        self._perf({
            "evt": "kafka_publish",
            "mid": mid,
            "topic": topic,
            "ms": kafka_ms,
            "expected_items": expected,
            "processed_items": processed,
        })
        logging.info(f"[strelka_flow] 📤✅ mid={mid} stage=publish action=completed topic=email.files.analysis status=success")

    def _finalize_artifact(self, root_id: str, expire_at: int) -> None:
        """Fan-out finalizer: invoked by whichever worker drives the artifact
        pending counter to 0. Reconstructs the events list and the original
        request context from Redis, calls aggregate_and_publish exactly once
        for this artifact, then signals FIN to the frontend and cleans up the
        per-artifact keys.
        """
        if not self.coordinator:
            return

        t_start = time.monotonic()
        meta_raw = self.coordinator.get(f"art:{root_id}:meta")
        trace_id_finalize = root_id
        mid_finalize = root_id
        root_enqueued_at = None
        if not meta_raw:
            logging.warning(
                f"[strelka_flow] ⚠️ stage=finalize action=missing_meta root_id={root_id} status=warning"
            )
            request_meta = {}
            root_file_name = ""
        else:
            try:
                meta_blob = json.loads(meta_raw)
            except Exception:
                logging.exception("finalize_artifact: bad meta")
                meta_blob = {}
            request_meta = meta_blob.get("request_meta") or {}
            root_file_name = meta_blob.get("root_file_name") or ""
            trace_id_finalize = meta_blob.get("trace_id") or root_id
            mid_finalize = meta_blob.get("mid") or (request_meta.get("mid") or root_id)
            root_enqueued_at = meta_blob.get("root_enqueued_at")

        # ── stage: finalize start ────────────────────────────────────────
        self._stage_event(
            mid_finalize, trace_id_finalize, "finalize", "start",
            root_id=root_id,
        )

        raw_events = self.coordinator.lrange(f"art:{root_id}:events", 0, -1) or []
        events: list = []
        for r in raw_events:
            try:
                events.append(json.loads(r))
            except Exception:
                continue

        # Locate the root file's own event for the root_file payload.
        root_file_dict: Optional[dict] = None
        for e in events:
            tree = (e.get("file") or {}).get("tree") or {}
            if tree.get("node") == root_id:
                root_file_dict = e.get("file")
                break
        if root_file_dict is None:
            root_file_dict = {"name": root_file_name}

        class _ProxyFile:
            def __init__(self, d: dict, name: str) -> None:
                self._d = d
                self.name = name

            def dictionary(self) -> dict:
                return self._d

        proxy = _ProxyFile(root_file_dict, root_file_name)

        # ── stage: publish ───────────────────────────────────────────────
        self._stage_event(
            mid_finalize, trace_id_finalize, "publish", "start",
            root_id=root_id, n_events=len(events),
        )
        t_pub = time.monotonic()
        # aggregate_and_publish only uses root_file.name and root_file.dictionary()
        self.aggregate_and_publish(root_id, proxy, events, request_meta)  # type: ignore[arg-type]
        publish_ms = (time.monotonic() - t_pub) * 1000.0
        self._stage_record(root_id, "publish", publish_ms, expire_at)
        self._stage_event(
            mid_finalize, trace_id_finalize, "publish", "end",
            duration_ms=publish_ms, root_id=root_id,
        )

        # Signal completion to the frontend and reap the per-artifact keys.
        fin_p = self.coordinator.pipeline(transaction=False)
        fin_p.rpush(f"event:{root_id}", "FIN")
        fin_p.expireat(f"event:{root_id}", expire_at)
        fin_p.execute()

        finalize_ms = (time.monotonic() - t_start) * 1000.0
        self._stage_record(root_id, "finalize", finalize_ms, expire_at)
        self._stage_event(
            mid_finalize, trace_id_finalize, "finalize", "end",
            duration_ms=finalize_ms, root_id=root_id,
        )

        # ── email_summary ────────────────────────────────────────────────
        try:
            stages_raw = self.coordinator.hgetall(f"art:{root_id}:stages") or {}
            workers_raw = self.coordinator.smembers(f"art:{root_id}:workers") or set()
        except Exception:
            stages_raw, workers_raw = {}, set()

        def _dec(v):
            if isinstance(v, bytes):
                v = v.decode()
            try:
                return round(float(v), 3)
            except (TypeError, ValueError):
                return 0.0

        stages = {
            (k.decode() if isinstance(k, bytes) else k): _dec(v)
            for k, v in stages_raw.items()
        }
        for s in self.STAGES:
            stages.setdefault(s, 0.0)

        if root_enqueued_at is not None:
            try:
                total_wall_ms = (time.time() - float(root_enqueued_at)) * 1000.0
            except (TypeError, ValueError):
                total_wall_ms = sum(stages.values())
        else:
            total_wall_ms = sum(stages.values())

        # Bottleneck = the stage with the highest accumulated CPU time. Tie
        # break to the leftmost in STAGES so output is deterministic.
        bottleneck = max(self.STAGES, key=lambda s: (stages.get(s, 0.0), -self.STAGES.index(s)))

        # ── Per-file metadata + correlation analytics ────────────────────
        files_meta, file_totals = self._file_metadata_from_events(events)
        # Top 3 slowest files (by analysis_time_ms).
        top_slow = sorted(
            files_meta, key=lambda f: f["analysis_time_ms"], reverse=True
        )[:3]
        # Average ms per KB across all non-empty files (size > 0).
        sized = [f for f in files_meta if f["size_bytes"] > 0]
        if sized:
            ms_per_kb_avg = round(
                sum(f["analysis_time_ms"] for f in sized)
                / sum(f["size_bytes"] / 1024.0 for f in sized),
                3,
            )
        else:
            ms_per_kb_avg = None
        heavy_flags = self._heavy_file_flags(
            files_meta, file_totals["total_file_analysis_ms"]
        )
        status = "FAILED" if any(
            (e.get("scan") or {}).get("ScanError") for e in events
        ) else "SUCCESS"

        summary = {
            "evt": "email_summary",
            "mid": mid_finalize,
            "trace_id": trace_id_finalize,
            "root_id": root_id,
            "total_processing_time_ms": round(float(total_wall_ms), 3),
            "stages": stages,
            "bottleneck_stage": bottleneck,
            "n_files": len(events),
            "workers": sorted(
                w.decode() if isinstance(w, bytes) else w for w in workers_raw
            ),
            # New: per-file metadata + bottleneck analytics
            "files": files_meta,
            "total_files": file_totals["total_files"],
            "total_size_bytes": file_totals["total_size_bytes"],
            "total_size_human": file_totals["total_size_human"],
            "total_file_analysis_ms": file_totals["total_file_analysis_ms"],
            "top_slowest_files": [
                {k: v for k, v in f.items() if k != "scanners"} for f in top_slow
            ],
            "ms_per_kb_avg": ms_per_kb_avg,
            "heavy_file_bottlenecks": heavy_flags,
            "status": status,
        }
        self._perf(summary)

        if self._pretty_trace_log:
            try:
                fmt = self._trace_format
                if fmt == "rich":
                    print(self._render_email_trace_block(summary), flush=True)
                elif fmt == "both":
                    print(self._render_simple_trace_block(summary), flush=True)
                    print(self._render_email_trace_block(summary), flush=True)
                else:  # "simple" (default)
                    print(self._render_simple_trace_block(summary), flush=True)
            except Exception:
                pass

        try:
            cleanup_p = self.coordinator.pipeline(transaction=False)
            cleanup_p.delete(f"art:{root_id}:events")
            cleanup_p.delete(f"art:{root_id}:counters")
            cleanup_p.delete(f"art:{root_id}:meta")
            cleanup_p.delete(f"art:{root_id}:stages")
            cleanup_p.delete(f"art:{root_id}:workers")
            cleanup_p.execute()
        except Exception:
            pass

        self._perf({
            "evt": "artifact_finalize",
            "mid": mid_finalize,
            "trace_id": trace_id_finalize,
            "root_id": root_id,
            "ms": finalize_ms,
            "n_events": len(events),
        })

    def _decode_email_context(self, mid: str, email_context_b64: str) -> dict:
        if not email_context_b64:
            return {}
        try:
            return json.loads(base64.b64decode(email_context_b64).decode("utf-8"))
        except Exception as ex:
            logging.warning(f"[strelka_flow] ⚠️ mid={mid} stage=aggregation action=partial reason=bad_email_context_b64 status=warning")
            logging.debug(f"email context decode error: {ex}")
            return {}

    def _json_sanitize(self, obj):
        """
        Make scanner output JSON-safe.
        Some scanners emit raw bytes/bytearray in events; wrap them in a stable base64 envelope.
        """
        if isinstance(obj, (bytes, bytearray)):
            return {"_type": "bytes", "encoding": "base64", "data": base64.b64encode(bytes(obj)).decode("utf-8")}
        if isinstance(obj, dict):
            return {str(k): self._json_sanitize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._json_sanitize(v) for v in obj]
        if isinstance(obj, tuple):
            return [self._json_sanitize(v) for v in obj]
        return obj

    def _derive_request_type(self, file_name: str) -> str:
        if "___urls" in (file_name or ""):
            return "urls"
        return "files"

    def _safe_int(self, value, default: int) -> int:
        try:
            return int(value)
        except Exception:
            return default

    def _build_final_payload(self, mid: str, email_context: dict, artifact_items: list[dict], expected: int, processed: int) -> dict:
        try:
            final_payload = dict(email_context or {})
            final_payload["mid"] = mid
            final_payload.setdefault("urls", [])
            final_payload.setdefault("files", [])

            used_url_indexes = set()
            used_file_indexes = set()
            unmatched = 0
            archive_child_total = 0

            for item in artifact_items:
                artifact_type = (item.get("artifact_type") or "").lower()
                artifact_name = item.get("artifact_name") or ""
                artifact_index = self._safe_int(item.get("artifact_index"), 0)
                mapped = False

                if artifact_type == "urls":
                    mapped = self._map_url_analysis(
                        mid=mid,
                        payload=final_payload,
                        item=item,
                        artifact_name=artifact_name,
                        artifact_index=artifact_index,
                        used_indexes=used_url_indexes,
                    )
                elif artifact_type in ("files", "email_context"):
                    mapped, archive_child_count = self._map_file_analysis(
                        mid=mid,
                        payload=final_payload,
                        item=item,
                        artifact_name=artifact_name,
                        artifact_index=artifact_index,
                        used_indexes=used_file_indexes,
                    )
                    archive_child_total += archive_child_count
                else:
                    logging.warning(
                        f"[strelka_flow] ⚠️ mid={mid} stage=finalize action=unmatched_artifact status=warning reason=unknown_artifact_type:{artifact_type}"
                    )
                    unmatched += 1
                    continue

                if not mapped:
                    unmatched += 1
                    logging.warning(
                        f"[strelka_flow] ⚠️ mid={mid} stage=finalize action=unmatched_artifact status=warning reason=no_match_for:{artifact_type}:{artifact_name}"
                    )

            final_payload["aggregation"] = {
                "expected_items": expected,
                "processed_items": processed,
                "completed": processed >= expected,
                "artifact_count": len(artifact_items),
                "archive_child_count": archive_child_total,
                "unmatched_artifacts": unmatched,
                "completed_at": time.time(),
            }
            return final_payload
        except Exception as ex:
            logging.exception(
                f"[strelka_flow] ❌ mid={mid} stage=finalize action=failure status=failed error={ex}"
            )
            fallback = dict(email_context or {})
            fallback["mid"] = mid
            fallback["aggregation"] = {
                "expected_items": expected,
                "processed_items": processed,
                "completed": processed >= expected,
                "artifact_count": len(artifact_items),
                "finalize_error": str(ex),
                "completed_at": time.time(),
            }
            return fallback

    def _map_url_analysis(self, mid: str, payload: dict, item: dict, artifact_name: str, artifact_index: int, used_indexes: set) -> bool:
        urls = payload.get("urls") or []
        target_index = -1

        if artifact_name:
            for idx, url_item in enumerate(urls):
                if idx in used_indexes:
                    continue
                if (url_item.get("url") or "") == artifact_name:
                    target_index = idx
                    break

        if target_index < 0 and artifact_index > 0 and artifact_index <= len(urls):
            idx = artifact_index - 1
            if idx not in used_indexes:
                target_index = idx

        if target_index < 0:
            return False

        urls[target_index]["analysis"] = self._artifact_analysis_object(mid, item)
        used_indexes.add(target_index)
        logging.info(
            f"[strelka_flow] 🔄 mid={mid} stage=finalize action=map_analysis_to_url target={urls[target_index].get('url', artifact_name)} status=success"
        )
        return True

    def _map_file_analysis(self, mid: str, payload: dict, item: dict, artifact_name: str, artifact_index: int, used_indexes: set) -> tuple[bool, int]:
        files = payload.get("files") or []
        target_index = -1
        root_sha256 = self._extract_root_sha256(item)

        if root_sha256:
            for idx, file_item in enumerate(files):
                if idx in used_indexes:
                    continue
                if (file_item.get("sha256") or "") == root_sha256:
                    target_index = idx
                    break

        if target_index < 0 and artifact_name:
            for idx, file_item in enumerate(files):
                if idx in used_indexes:
                    continue
                if (file_item.get("filename") or "") == artifact_name:
                    target_index = idx
                    break

        if target_index < 0 and artifact_index > 0 and artifact_index <= len(files):
            idx = artifact_index - 1
            if idx not in used_indexes:
                target_index = idx

        if target_index < 0:
            return False, 0

        analysis_obj = self._artifact_analysis_object(mid, item)
        files[target_index]["analysis"] = analysis_obj
        used_indexes.add(target_index)
        child_count = len(analysis_obj.get("archive_children") or [])

        logging.info(
            f"[strelka_flow] 🔄 mid={mid} stage=finalize action=map_analysis_to_file target={files[target_index].get('filename', artifact_name)} status=success"
        )
        logging.info(
            f"[strelka_flow] 📦 mid={mid} stage=finalize action=map_archive_children target={files[target_index].get('filename', artifact_name)} child_count={child_count} status=success"
        )
        return True, child_count

    def _extract_root_sha256(self, item: dict) -> str:
        for ev in (item.get("events") or []):
            scan = ev.get("scan") or {}
            hash_obj = scan.get("hash") or {}
            sha256 = hash_obj.get("sha256")
            if sha256:
                return sha256
        return ""

    def _artifact_analysis_object(self, mid: str, item: dict) -> dict:
        events = item.get("events") or []
        root_event = events[0] if events else {}
        child_events = events[1:] if len(events) > 1 else []
        if root_event:
            logging.info(
                f"[strelka_flow] 🧹 mid={mid} stage=finalize action=deduplicate_root_event artifact={item.get('artifact_name', 'unknown')} status=success"
            )
        return {
            "artifact_type": item.get("artifact_type"),
            "artifact_name": item.get("artifact_name"),
            "root_event": root_event,
            "events": child_events,
            "archive_children": item.get("archive_children") or [],
            "counts": item.get("counts") or {},
        }

    def match_scanner(
        self,
        scanner: str,
        mappings: list,
        file: File,
        ignore_wildcards: Optional[bool] = False,
    ) -> dict:
        """Matches a scanner to mappings and file data.

        Performs the task of assigning a scanner based on the scan configuration
        mappings and file flavors, filename, and source. Assignment supports
        positive and negative matching: scanners are assigned if any positive
        categories are matched and no negative categories are matched. Flavors are
        literal matches, filename and source matches uses regular expressions.

        Args:
            scanner: Name of the scanner to be assigned.
            mappings: List of dictionaries that contain values used to assign
                the scanner.
            file: File object to use during scanner assignment.
            ignore_wildcards: Filter out wildcard scanner matches
        Returns:
            Dictionary containing the assigned scanner or None.
        """
        import fnmatch

        def _flavor_matches(pattern: str, file_flavors) -> bool:
            """Match a flavor pattern against the file's flavor set.
            Plain strings are exact-match (legacy behavior). Patterns
            containing '*' or '?' use glob semantics, so `application/*`
            matches `application/pdf`, `application/zip`, etc. This is
            additive: existing literal flavors in backend.yaml are
            unaffected.
            """
            flavors_iter = list(itertools.chain(*file_flavors.values()))
            if "*" in pattern or "?" in pattern:
                return any(fnmatch.fnmatchcase(f, pattern) for f in flavors_iter)
            return pattern in flavors_iter

        for mapping in mappings:
            negatives = mapping.get("negative", {})
            positives = mapping.get("positive", {})
            neg_flavors = negatives.get("flavors", [])
            neg_filename = negatives.get("filename", None)
            neg_source = negatives.get("source", [])
            pos_flavors = positives.get("flavors", [])
            pos_filename = positives.get("filename", None)
            pos_source = positives.get("source", [])
            assigned = {
                "name": scanner,
                "priority": mapping.get("priority", 5),
                "options": mapping.get("options", {}),
            }

            for neg_flavor in neg_flavors:
                if _flavor_matches(neg_flavor, file.flavors):
                    return {}
            if neg_filename:
                if re.search(neg_filename, file.name):
                    return {}
            if neg_source:
                if file.source in neg_source:
                    return {}
            for pos_flavor in pos_flavors:
                if pos_flavor == "*" and not ignore_wildcards:
                    return assigned
                if _flavor_matches(pos_flavor, file.flavors):
                    return assigned
            if pos_filename:
                if re.search(pos_filename, file.name):
                    return assigned
            if pos_source:
                if file.source in pos_source:
                    return assigned

        return {}

    def match_scanners(
        self, file: File, ignore_wildcards: Optional[bool] = False
    ) -> list:
        """
        Wraps match_scanner

        Args:
            file: File object to use during scanner assignment.
            ignore_wildcards: Filter out wildcard scanner matches.
        Returns:
            List of scanner dictionaries.
        """
        scanner_list = []

        for name in self.scanners:
            mappings = self.scanners.get(name, {})
            scanner = self.match_scanner(name, mappings, file, ignore_wildcards)
            if scanner:
                scanner_list.append(scanner)

        scanner_list.sort(
            key=lambda k: k.get("priority", 5),
            reverse=True,
        )
        print (scanner_list)
        return scanner_list


class IocOptions(object):
    """
    Defines an ioc options object that can be used to specify the ioc_type for developers as opposed to using a
    string.
    """

    domain = "domain"
    url = "url"
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"
    email = "email"
    ip = "ip"


class Scanner(object):
    """Defines a scanner that scans File objects.

    Each scanner inherits this class and overrides methods (init and scan)
    to perform scanning functions.

    Attributes:
        name: String that contains the scanner class name.
            This is referenced in the scanner metadata.
        key: String that contains the scanner's metadata key.
            This is used to identify the scanner metadata in scan results.
        event: Dictionary containing the result of scan
        backend_cfg: Dictionary that contains the parsed backend configuration.
        scanner_timeout: Amount of time (in seconds) that a scanner can spend
            scanning a file. Can be overridden on a per-scanner basis
            (see scan_wrapper).
        coordinator: Redis client connection to the coordinator.
    """

    def __init__(
        self,
        backend_cfg: dict,
        coordinator: Optional[redis.StrictRedis] = None,
        tracer: Optional[trace.Tracer] = None,
    ) -> None:
        """Inits scanner with scanner name and metadata key."""
        self.name = self.__class__.__name__
        self.key = inflection.underscore(self.name.replace("Scan", ""))
        self.scanner_timeout = backend_cfg.get("limits", {}).get("scanner", 10)
        self.coordinator = coordinator
        self.event: dict = dict()
        self.files: list = []
        self.flags: list[str] = []
        self.iocs: list = []
        self.tracer = tracer
        self.type = IocOptions
        self.extract = TLDExtract(suffix_list_urls=[])
        self.expire_at: int = 0

        if not self.tracer:
            self.tracer = trace.get_tracer(__name__)

        self.init()

    def init(self) -> None:
        """Overrideable init.

        This method can be used to setup one-time variables required
        during scanning."""

    def timeout_handler(self, signal_number: int, frame: Optional[FrameType]) -> None:
        """Signal ScannerTimeout"""
        raise ScannerTimeout

    def scan(self, data, file, options, expire_at) -> None:
        """Overrideable scan method.

        Args:
            data: Data associated with file that will be scanned.
            file: File associated with data that will be scanned (see File()).
            options: Options to be applied during scan.
            expire_at: Expiration date for any files extracted during scan.
        """
        pass

    def scan_wrapper(
        self, data: bytes, file: File, options: dict, expire_at: int
    ) -> Tuple[list[File], dict, list]:
        """Sets up scan attributes and calls scan method.

        Scanning code is wrapped in try/except for error handling.
        The scanner always returns a list of extracted files (which may be
        empty) and metadata regardless of whether the scanner completed
        successfully or hit an exception.

        Args:
            data: Data associated with file that will be scanned.
            file: File associated with data that will be scanned (see File()).
            options: Options to be applied during scan.
            expire_at: Expiration date for any files extracted during scan.
        Returns:
            List of extracted File objects (may be empty).
            Dictionary of scanner metadata.
        Raises:
            DistributionTimeout: interrupts the scan when distribution times out.
            RequestTimeout: interrupts the scan when request times out.
            Exception: Unknown exception occurred.
        """
        with self.tracer.start_as_current_span("scan") as current_span:
            start = time.time()
            self.event = dict()
            self.scanner_timeout = options.get(
                "scanner_timeout", self.scanner_timeout or 10
            )

            current_span.set_attribute(f"{__namespace__}.scanner.name", self.name)
            current_span.set_attribute(
                f"{__namespace__}.scanner.timeout", self.scanner_timeout
            )

            try:
                signal.signal(signal.SIGALRM, self.timeout_handler)
                signal.alarm(self.scanner_timeout)
                self.expire_at = expire_at
                self.scan(data, file, options, expire_at)
                signal.alarm(0)
            except ScannerTimeout:
                self.flags.append("timed_out")
            except (DistributionTimeout, RequestTimeout):
                raise
            except ScannerException as e:
                signal.alarm(0)
                self.event.update({"exception": e.message})
            except Exception as e:
                signal.alarm(0)
                logging.exception(
                    f"{self.name}: unhandled exception while scanning"
                    f' uid {file.uid if file else "_missing_"} (see traceback below)'
                )
                self.flags.append("uncaught_exception")
                self.event.update(
                    {"exception": "\n".join(traceback.format_exception(e, limit=-10))}
                )

            self.event = {
                **{"elapsed": round(time.time() - start, 6)},
                **{"flags": self.flags},
                **self.event,
            }

            # Removes duplicate entries from IOC list
            unique_iocs = []
            seen = set()
            for ioc in self.iocs:
                identifier = (
                    ioc["ioc"],
                    ioc["ioc_type"],
                )  # Unique identifier based on 'ioc' and 'ioc_type'
                if identifier not in seen:
                    seen.add(identifier)
                    unique_iocs.append(ioc)

            self.iocs = unique_iocs

            return self.files, {self.key: self.event}, self.iocs

    def emit_file(
        self, data: bytes, name: str = "", flavors: Optional[list[str]] = None
    ) -> None:
        """Re-ingest extracted file"""

        with self.tracer.start_as_current_span("emit_file") as current_span:
            try:
                extract_file = File(
                    name=name,
                    source=self.name,
                )
                if flavors:
                    extract_file.add_flavors({"external": flavors})

                current_span.set_attribute(f"{__namespace__}.file.name", name)
                current_span.set_attribute(f"{__namespace__}.file.size", len(data))
                current_span.set_attribute(f"{__namespace__}.file.source", self.name)

                if self.coordinator:
                    for c in chunk_string(data):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            self.expire_at,
                        )
                else:
                    extract_file.data = data

                self.files.append(extract_file)

            except Exception:
                logging.exception("failed to emit file")
                self.flags.append("failed_to_emit_file")

    def upload_to_coordinator(self, pointer, chunk, expire_at) -> None:
        """Uploads data to coordinator.

        This method is used during scanning to upload data to coordinator,
        where the data is later pulled from during file distribution.

        Args:
            pointer: String that contains the location of the file bytes
                in Redis.
            chunk: String that contains a chunk of data to be added to
                the coordinator.
            expire_at: Expiration date for data stored in pointer.
        """
        if self.coordinator:
            p = self.coordinator.pipeline(transaction=False)
            p.rpush(f"data:{pointer}", chunk)
            p.expireat(f"data:{pointer}", expire_at)
            p.execute()

    def process_ioc(self, ioc, scanner_name) -> None:
        """
        Processes an Indicator of Compromise (IOC) and appends it to the scanner's IOC list.

        This method takes an IOC (such as a URL, domain, IP address, or email) and categorizes it
        into an appropriate type. It validates the IOC using various validators and regular expressions,
        then appends a dictionary containing the IOC, its type, and the scanner name to the scanner's IOC list.
        If the IOC does not match any valid type, a warning is logged, and the IOC is not added.

        Args:
            ioc (str or bytes): The IOC to be processed. Can be a string or bytes.
                                If bytes, it will be decoded to a string.
            scanner_name (str): The name of the scanner processing the IOC. This is used to tag the IOC
                                in the appended dictionary.

        Note:
            - The method internally handles different formats and types of IOCs (like URLs, domains, IPs, and emails).
            - If the IOC is invalid or does not match a known pattern, a warning is logged and the IOC is not added.
        """
        if not ioc:
            return

        if validators.url(ioc):
            ioc_type = "url"
            netloc = urlparse(ioc).netloc

            if validators.ipv4(netloc):
                self.process_ioc(
                    netloc,
                    scanner_name,
                )
            elif validators.ipv6(netloc):
                self.process_ioc(
                    netloc,
                    scanner_name,
                )
            elif validators.domain(netloc):
                self.process_ioc(
                    netloc,
                    scanner_name,
                )
        elif validators.domain(ioc):
            ioc_type = "domain"
        elif re.match(r"^[\w\.\-]{2,62}\.[a-zA-Z]{2,5}:\d{1,5}$", ioc):
            ioc_type = "domain"
            ioc = ioc.split(":")[0]
        elif validators.ipv4(ioc):
            ioc_type = "ip"
        elif validators.ipv6(ioc):
            ioc_type = "ip"
        elif validators.email(ioc):
            ioc_type = "email"
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$", ioc):
            ioc_type = "ip"
            ioc = ioc.split(":")[0]
        else:
            logging.warning(f"{ioc} does not match a valid IOC type")
            return

        self.iocs.append(
            {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "scanner": scanner_name,
            }
        )

    def add_iocs(self, ioc) -> None:
        """Adds ioc to the iocs.
        :param ioc: The IOC or list of IOCs to be added. All iocs must be of the same type. Must be type String or Bytes.
        """
        try:
            if isinstance(ioc, list):
                for i in ioc:
                    if isinstance(i, bytes):
                        i = i.decode()
                    if not isinstance(i, str):
                        logging.warning(
                            f"Could not process {i} from {self.name}: Type {type(i)} is"
                            " not type Bytes or String"
                        )
                        continue
                    self.process_ioc(
                        i,
                        self.name,
                    )
            else:
                if isinstance(ioc, bytes):
                    ioc = ioc.decode()
                if not isinstance(ioc, str):
                    logging.warning(
                        f"Could not process {ioc} from {self.name}: Type {type(ioc)} is"
                        " not type Bytes or String"
                    )
                    return
                self.process_ioc(
                    ioc,
                    self.name,
                )
        except Exception as e:
            logging.error(f"Failed to add {ioc} from {self.name}: {e}")


def chunk_string(s, chunk=1024 * 16) -> Generator[bytes, None, None]:
    """Takes an input string and turns it into smaller byte pieces.

    This method is required for inserting data into coordinator.

    Yields:
        Chunks of the input string.
    """
    if isinstance(s, bytearray):
        s = bytes(s)

    for c in range(0, len(s), chunk):
        yield s[c : c + chunk]


def format_event(metadata: dict) -> str:
    """Formats file metadata into an event.

    This function must be used on file metadata before the metadata is
    pushed to Redis. The function takes a dictionary containing a
    complete file event and runs the following (sequentially):
        * Replaces all bytes with strings
        * Removes all values that are empty strings, empty lists,
            empty dictionaries, or None
        * Dumps dictionary as JSON

    Args:
        metadata: Dictionary that needs to be formatted into an event.

    Returns:
        JSON-formatted file event.
    """

    def visit(path, key, value):
        if isinstance(value, (bytes, bytearray)):
            value = str(value, encoding="UTF-8", errors="replace")
        return key, value

    remap1 = iterutils.remap(metadata, visit=visit)
    remap2 = iterutils.remap(
        remap1,
        lambda p, k, v: v != "" and v != [] and v != {} and v is not None,
    )

    try:
        return json.dumps(remap2)
    except Exception:
        logging.exception(f"Failed to serialize event {remap2}")
        return json.dumps({})

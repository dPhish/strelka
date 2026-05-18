import os
from io import BytesIO

import clamd

from strelka import strelka


class ScanClamav(strelka.Scanner):
    """Streams the file's bytes to clamd via INSTREAM over a Unix socket.

    The previous implementation shelled out to `clamscan` for every file
    (cold-loading the ~1 GB signature DB each time) and ran `freshclam`
    before every scan. Both have been removed. The clamd daemon holds the
    DB resident; a query costs O(scan-time), typically 5-30 ms per file.

    Scanner Type: Collection

    Output fields:
        status:     "OK" | "FOUND" | "ERROR" | "UNKNOWN" | "skipped_oversize"
        signature:  ClamAV signature name (set only when status == "FOUND")
        size_bytes: original payload size (set when skipped_oversize)

    Flags:
        clamd_unavailable, clamd_connection_error, clamd_retry_failed,
        clamav_scan_error, clamav_signature_match, clamav_skipped_oversize
    """
    SOCKET = os.environ.get("CLAMD_SOCKET", "").strip()
    HOST = os.environ.get("CLAMD_HOST", "clamd")
    PORT = int(os.environ.get("CLAMD_PORT", "3310"))

    _client = None

    @classmethod
    def _get_client(cls):
        if cls._client is None:
            if cls.SOCKET:
                cls._client = clamd.ClamdUnixSocket(path=cls.SOCKET, timeout=30)
            else:
                cls._client = clamd.ClamdNetworkSocket(
                    host=cls.HOST, port=cls.PORT, timeout=30
                )
        return cls._client

    @classmethod
    def _reset_client(cls):
        cls._client = None

    def scan(self, data, file, options, expire_at):
        max_bytes = int(options.get("max_bytes", 100 * 1024 * 1024))
        if len(data) > max_bytes:
            self.flags.append("clamav_skipped_oversize")
            self.event["status"] = "skipped_oversize"
            self.event["size_bytes"] = len(data)
            return

        try:
            client = self._get_client()
        except Exception:
            self.flags.append("clamd_unavailable")
            return

        try:
            res = client.instream(BytesIO(data))
        except clamd.ConnectionError:
            self.flags.append("clamd_connection_error")
            self._reset_client()
            try:
                res = self._get_client().instream(BytesIO(data))
            except Exception:
                self.flags.append("clamd_retry_failed")
                return
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("clamav_scan_error")
            raise

        verdict, signature = res.get("stream", (None, None))
        self.event["status"] = verdict or "UNKNOWN"
        if verdict == "FOUND":
            self.event["signature"] = signature
            self.flags.append("clamav_signature_match")
        elif verdict == "ERROR":
            self.flags.append("clamav_scan_error")
            self.event["error"] = str(signature) if signature else "unknown"

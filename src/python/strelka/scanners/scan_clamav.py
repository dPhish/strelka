import socket
import struct

from strelka import strelka


class ScanClamav(strelka.Scanner):
    """
    This scanner streams file data to a running ClamAV daemon (clamd) using its INSTREAM protocol and
    returns a determination if the file is infected or not, based on the ClamAV signature database
    loaded by that daemon.

    Scanner Type: Collection

    Attributes:
        None

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Scan Determination**
            - This scanner provides an initial determination on a file if it is infected or not based on
              the ClamAV signature database loaded by the clamd daemon it connects to.

    ## Known Limitations
    !!! warning "Known Limitations"
        - **ClamAV Signature Database**
            - This scanner relies on the ClamAV signature database which is not necesarily all-encompassing. Though
              the scanner may return a determination, users should be advise that this is not exaustive.
        - **Requires a reachable clamd daemon**
            - This scanner does not run ClamAV locally and does not manage signature updates. It requires a clamd
              daemon reachable at `clamd_host`:`clamd_port` (options) on the backend's network; that daemon is
              responsible for keeping its own signature database up to date (e.g. via its own freshclam process).

    ## Options
    !!! info "Options"
        - `clamd_host` -- hostname/IP of the clamd daemon (defaults to `clamd`)
        - `clamd_port` -- TCP port of the clamd daemon (defaults to `3310`)
        - `clamd_timeout` -- socket connect/read timeout in seconds (defaults to `30`)

    ## References
    !!! quote "References"
    - [ClamAV Documentation Source](https://docs.clamav.net/Introduction.html)
    - [clamd usage / INSTREAM protocol](https://docs.clamav.net/manual/Usage/Scanning.html#clamd)
    - [BlogPost on ClamAV Scanner](https://simovits.com/strelka-let-us-build-a-scanner/)

    ## Contributors
    !!! example "Contributors"
        - [Sara Kalupa](https://github.com/skalupa)

    """

    CHUNK_SIZE = 8192

    def scan(self, data, file, options, expire_at):
        host = options.get("clamd_host", "clamd")
        port = options.get("clamd_port", 3310)
        timeout = options.get("clamd_timeout", 30)

        try:
            reply = self._instream(data, host, port, timeout)
        except (OSError, socket.timeout) as e:
            self.flags.append("clamd_connection_error")
            self.event["error"] = str(e)
            return

        # Expected replies: "stream: OK", "stream: <Signature> FOUND", "stream: <reason> ERROR"
        _, _, verdict = reply.partition(": ")

        if verdict == "OK":
            self.event["infected"] = False
        elif verdict.endswith(" FOUND"):
            self.event["infected"] = True
            self.event["signature"] = verdict[: -len(" FOUND")]
        else:
            self.flags.append("clamd_unexpected_response")
            self.event["raw_response"] = reply

    def _instream(self, data: bytes, host: str, port: int, timeout: float) -> str:
        """Streams file data to clamd's INSTREAM command and returns its reply."""
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"zINSTREAM\0")

            for offset in range(0, len(data), self.CHUNK_SIZE):
                chunk = data[offset : offset + self.CHUNK_SIZE]
                sock.sendall(struct.pack(">L", len(chunk)) + chunk)

            sock.sendall(struct.pack(">L", 0))  # zero-length chunk ends the stream

            response = b""
            while b"\0" not in response:
                buf = sock.recv(4096)
                if not buf:
                    break
                response += buf

        return response.decode("utf-8", errors="replace").strip("\x00").strip()

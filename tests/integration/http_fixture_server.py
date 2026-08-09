from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"B" * 4096


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "BenmapFixture/1.0"
    protocol_version = "HTTP/1.1"

    def _headers(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "close")
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802 - HTTP handler API
        self._headers()

    def do_GET(self) -> None:  # noqa: N802 - HTTP handler API
        self._headers()
        self.wfile.write(BODY)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port), FixtureHandler).serve_forever()


if __name__ == "__main__":
    main()

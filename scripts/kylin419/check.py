# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import http.client
import json
from pathlib import Path
import re
import socket
import sys
import time


TRACE = "1234567890abcdef1234567890abcdef"
PARENT = "1234567890abcdef"
HEADER = f"00-{TRACE}-{PARENT}-01"
FRAGMENTS = 100


def fragment():
    with socket.create_connection(("127.0.0.1", 18081), timeout=5) as conn:
        for i in range(FRAGMENTS):
            size = 81920 if i % 2 else 0
            path = f"/fragment/h1/{i}"
            request = (
                f"POST {path} HTTP/1.1\r\nHost: test\r\n"
                f"Content-Type: application/octet-stream\r\nContent-Length: {size}\r\n\r\n"
            ).encode() + b"x" * size
            conn.sendall(request[:1])
            time.sleep(0.01)
            conn.sendall(request[1:])
            with http.client.HTTPResponse(conn) as response:
                response.begin()
                assert response.status == 200 and f"body={size} " in response.read().decode()
            print(path)


def verify(mode):
    logs = Path("logs")
    output = (logs / f"{mode}.obi.log").read_text(errors="replace")
    assert "socket context propagation disabled because sockhash receive semantics could not be verified" in output
    assert "empty connected socket returned n=0 without EAGAIN" in output
    spans = [
        span
        for line in output.splitlines()
        if line.startswith('[{"type":')
        for span in json.loads(line)
    ]

    if mode == "generic":
        servers = {
            span["attributes"]["url"]: span for span in spans if span["type"] == "HTTP"
        }
        for i in range(FRAGMENTS):
            assert servers[f"/fragment/h1/{i}"]["attributes"]["status"] == "200"
        for i in range(12):
            for size in (0, 81920):
                span = servers[f"/probe/h2/size{size}/{i}"]
                assert span["traceID"] == TRACE and span["parentSpanID"] == PARENT, span
        metrics = (logs / "generic.metrics").read_text()
        for metric in (
            "dns_lookup_duration_seconds_count",
            "obi_stat_tcp_successful_connections_total",
            "obi_stat_tcp_failed_connections_total",
            "obi_stat_tcp_rtt_seconds_count",
        ):
            assert re.search(rf"^{metric}[{{ ]", metrics, re.M), metric
        assert any(span["type"] == "GRPC" for span in spans), "missing gRPC server span"
        print(f"Generic traffic passed ({FRAGMENTS} split HTTP/1, 24 HTTP/2 parents, gRPC, DNS and TCP metrics)")
        return

    # The two client runs use the same paths. Match the observed wire header
    # against any client span for that exact path.
    client_spans = {
        (span["attributes"]["url"], span["traceID"], span["spanID"])
        for span in spans
        if span["type"] == "HTTPClient"
    }
    for headers in ("inject", "preserve"):
        lines = (logs / f"{headers}.log").read_text().splitlines()
        http = grpc = 0
        for line in lines:
            if not line.startswith(("HTTP/", "grpc ")):
                continue
            match = re.search(r" traceparent=(00-([0-9a-f]{32})-([0-9a-f]{16})-0[01]) traceparent_count=1$", line)
            assert match, line
            if headers == "preserve":
                assert match[1] == HEADER, line
            if line.startswith("HTTP/"):
                http += 1
                if headers == "inject":
                    assert (line.split()[1], match[2], match[3]) in client_spans, line
            else:
                grpc += 1
                assert line.startswith("grpc SERVING "), line
        assert (http, grpc) == (192, 48), (headers, http, grpc)
        print(f"Go Header {headers} passed ({http} HTTP and {grpc} gRPC requests)")


if sys.argv[1] == "fragment":
    fragment()
else:
    verify(sys.argv[1])

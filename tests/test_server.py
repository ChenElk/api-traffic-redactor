"""Integration tests of the HTTP service, against a real server.

Most tests talk to one `python -m redactor --serve` process over real
sockets, so what is checked is what a client sees: status codes, headers, the
exact bytes of the body and the framing of the response. The log of that
process (stdout and stderr together) is checked for what must never be in it.
"""

import contextlib
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import tracemalloc
from pathlib import Path

import pytest
import uvicorn

from redactor.cli import EXIT_IO_ERROR, EXIT_OK, EXIT_USAGE, _build_parser
from redactor.engine import Redactor
from redactor.rules import load_rules
from redactor.server import create_app
from redactor.stream import DEFAULT_MAX_LINE_BYTES, RedactionStream

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules(ROOT / "rules.yaml")
SAMPLE = (ROOT / "input.ndjson").read_bytes()
HOST = "127.0.0.1"

RECORD = b'{"body":{"password":"hunter2","user":"dana@example.com"}}\n'
LAST_CHUNK = b"0\r\n\r\n"
DISCONNECTED = "connection closed before the request ended"


def expected_output(data: bytes) -> bytes:
    """What the stream produces in-process for the same input."""
    stream = RedactionStream(Redactor(RULES))
    return stream.feed(data) + stream.finish()


REDACTED_RECORD = expected_output(RECORD)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        return probe.getsockname()[1]


def port_is_open(port: int) -> bool:
    try:
        socket.create_connection((HOST, port), timeout=1).close()
    except OSError:
        return False
    return True


class Service:
    """A `redactor --serve` process on a free local port, and its log."""

    def __init__(self, directory: Path, *extra_args: str, rules: Path = ROOT / "rules.yaml", port: int | None = None):
        self.port = port or free_port()
        self.log_path = directory / f"service-{self.port}-{time.monotonic_ns()}.log"
        self._log_file = open(self.log_path, "wb")
        self.process = subprocess.Popen(
            [sys.executable, "-m", "redactor", "--serve", "--addr", f"{HOST}:{self.port}", "--rules", str(rules), *extra_args],
            cwd=ROOT,
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
            # On Windows a process needs its own group to be sent Ctrl+Break alone.
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )

    def wait_until_up(self, timeout: float = 30) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self.process.poll() is None:
            if port_is_open(self.port):
                return True
            time.sleep(0.05)
        return False

    def log(self) -> str:
        return self.log_path.read_text(encoding="utf-8", errors="replace")

    def wait_for_log(self, text: str, count: int = 1, timeout: float = 10) -> bool:
        """Wait until `text` appears at least `count` times in the log."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.log().count(text) >= count:
                return True
            time.sleep(0.05)
        return False

    def signal_stop(self) -> None:
        """Ask the process to stop the way an operator or Kubernetes would."""
        self.process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)

    def stop(self) -> int:
        if self.process.poll() is None:
            self.signal_stop()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=15)
        self._log_file.close()
        return self.process.returncode


@pytest.fixture(scope="module")
def service(tmp_path_factory):
    """One service process shared by the tests of this module."""
    running = Service(tmp_path_factory.mktemp("service"))
    assert running.wait_until_up(), running.log()
    yield running
    running.stop()


def request(port: int, method: str, path: str, body=None, headers: dict | None = None, timeout: float = 30):
    """Send one request; return (status, headers with lower-case names, body)."""
    connection = http.client.HTTPConnection(HOST, port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, {name.lower(): value for name, value in response.getheaders()}, response.read()
    finally:
        connection.close()


def chunk(data: bytes) -> bytes:
    """One chunk of a body sent with Transfer-Encoding: chunked."""
    return b"%x\r\n%s\r\n" % (len(data), data)


def open_chunked_post(port: int, path: bytes = b"/redact") -> socket.socket:
    """Open a connection and send the head of a chunked POST; the body is up to the caller."""
    sock = socket.create_connection((HOST, port))
    sock.settimeout(10)
    sock.sendall(b"POST " + path + b" HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n")
    return sock


def read_until(sock: socket.socket, marker: bytes) -> bytes:
    """Read until `marker` has arrived, the peer closes, or the socket times out."""
    received = b""
    with contextlib.suppress(socket.timeout, ConnectionError):
        while marker not in received:
            piece = sock.recv(65536)
            if not piece:
                break
            received += piece
    return received


def read_to_end(sock: socket.socket) -> bytes:
    """Read until the peer closes the connection."""
    received = b""
    with contextlib.suppress(socket.timeout, ConnectionError):
        while piece := sock.recv(65536):
            received += piece
    return received


def post_while_reading(port: int, pieces, consume, timeout: float = 120) -> int:
    """POST `pieces` as a chunked body from a second thread while this thread reads the response.

    A streaming service sends output while it is still receiving input, so a
    client has to read while it sends. `consume(data, progress)` is called
    for each piece of the decoded response body; `progress["sent"]` is the
    number of body bytes sent so far and `progress["done"]` turns true when
    the whole request has been sent. Returns the status code.
    """
    connection = http.client.HTTPConnection(HOST, port, timeout=timeout)
    connection.putrequest("POST", "/redact")
    connection.putheader("Transfer-Encoding", "chunked")
    connection.endheaders()
    progress = {"sent": 0, "done": False}

    def send() -> None:
        with contextlib.suppress(OSError):  # the test may close the connection on purpose
            for piece in pieces:
                connection.send(chunk(piece))
                progress["sent"] += len(piece)
            connection.send(LAST_CHUNK)
        progress["done"] = True

    sender = threading.Thread(target=send)
    sender.start()
    try:
        response = connection.getresponse()
        while data := response.read1(65536):
            consume(data, progress)
        return response.status
    finally:
        sender.join()
        connection.close()


@contextlib.contextmanager
def in_process_service(max_line_bytes: int = DEFAULT_MAX_LINE_BYTES):
    """Run the application inside this process, for the test that measures memory."""
    port = free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_app(RULES, max_line_bytes), host=HOST, port=port, access_log=False, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 30
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started
    try:
        yield port
    finally:
        server.should_exit = True
        thread.join(timeout=15)


# --- the two endpoints --------------------------------------------------------


def test_healthz_answers_200(service):
    status, headers, body = request(service.port, "GET", "/healthz")
    assert status == 200
    assert headers["content-type"] == "application/json"
    assert json.loads(body) == {"status": "ok"}


def test_redact_with_a_content_length_body(service):
    status, headers, body = request(service.port, "POST", "/redact", body=SAMPLE)
    assert status == 200
    assert headers["content-type"] == "application/x-ndjson"
    assert body == expected_output(SAMPLE)


def test_redact_with_a_chunked_body(service):
    pieces = (SAMPLE[start : start + 700] for start in range(0, len(SAMPLE), 700))
    # Given an iterator and no Content-Length, http.client sends the body
    # with Transfer-Encoding: chunked.
    status, _, body = request(service.port, "POST", "/redact", body=pieces)
    assert status == 200
    assert body == expected_output(SAMPLE)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b'{"a":1}',  # last line without a newline
        b'{"a":1}\r\n{"password":"x"}\r\n',  # CRLF
        b'\n   \n{"a":1}\n\n',  # blank lines
        b"\xef\xbb\xbf" + RECORD,  # byte order mark
        b'{"a":1}\n{"name":"caf\xe9"}\n{"b":2}\n',  # a line that is not UTF-8
        RECORD * 3 + b'{"password":"hunter2"\n' + RECORD,  # a broken line among good ones
    ],
    ids=["empty body", "no final newline", "CRLF", "blank lines", "BOM", "invalid UTF-8", "broken line"],
)
def test_every_input_line_gives_the_output_line_of_the_stream(service, data):
    status, _, body = request(service.port, "POST", "/redact", body=data)
    assert status == 200
    assert body == expected_output(data)
    assert body.count(b"\n") == len(expected_output(data).splitlines())


def test_a_broken_line_is_replaced_and_the_status_stays_200(service):
    data = (
        b'{"body":{"password":"first"}}\n'
        b'{"body":{"password":"hunter2"}\n'  # one closing brace short
        b'{"body":{"password":"third"}}\n'
    )
    status, _, body = request(service.port, "POST", "/redact", body=data)
    assert status == 200
    assert body.split(b"\n") == [
        b'{"body":{"password":"****"}}',
        b'{"redactor_error":"invalid_json","line":2}',
        b'{"body":{"password":"****"}}',
        b"",
    ]
    assert b"hunter2" not in body


def test_a_line_over_one_mebibyte_is_replaced_and_the_limit_itself_is_allowed(service):
    # The filler is spaces: letters would hit the e-mail pattern's backtracking.
    at_limit = b'{"k":"' + b" " * (DEFAULT_MAX_LINE_BYTES - 8) + b'"}'
    over_limit = b'{"password":"over-limit-secret","k":"' + b" " * DEFAULT_MAX_LINE_BYTES + b'"}'
    data = at_limit + b"\n" + over_limit + b"\n" + RECORD
    status, _, body = request(service.port, "POST", "/redact", body=data)
    assert status == 200
    assert body == at_limit + b'\n{"redactor_error":"line_too_long","line":2}\n' + REDACTED_RECORD
    # Nothing of the discarded line is passed on.
    assert b"over-limit-secret" not in body


# --- paths and methods --------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("GET", "/redact", 405),
        ("PUT", "/redact", 405),
        ("DELETE", "/redact", 405),
        ("POST", "/healthz", 405),
        ("GET", "/", 404),
        ("GET", "/nothing", 404),
        ("POST", "/redact/extra", 404),
        ("GET", "/openapi.json", 404),  # the generated schema and its pages are switched off
        ("GET", "/docs", 404),
        ("GET", "/redoc", 404),
    ],
)
def test_other_paths_and_methods_are_refused(service, method, path, expected):
    body = RECORD if method in ("POST", "PUT") else None
    status, _, answer = request(service.port, method, path, body=body)
    assert status == expected
    # The answer is a fixed text. It echoes neither the path nor the body.
    assert json.loads(answer) in ({"detail": "Not Found"}, {"detail": "Method Not Allowed"})


# --- requests that are not valid HTTP -----------------------------------------


def test_a_request_that_is_not_http_gets_400(service):
    sock = socket.create_connection((HOST, service.port))
    sock.settimeout(10)
    sock.sendall(b"THIS IS NOT HTTP hunter2\r\n\r\n")
    answer = read_to_end(sock)
    sock.close()
    assert answer.startswith(b"HTTP/1.1 400 ")
    assert b"hunter2" not in answer


def test_a_malformed_body_before_any_output_gets_400(service):
    # "zz" is not a chunk size. Nothing has been answered yet, so the server
    # can still send a status of its own.
    sock = open_chunked_post(service.port)
    sock.sendall(b"zz\r\nhunter2\r\n")
    answer = read_to_end(sock)
    sock.close()
    assert answer.startswith(b"HTTP/1.1 400 ")
    assert b"hunter2" not in answer


def test_a_malformed_body_after_output_started_cuts_the_response_off(service):
    # The first line was answered with status 200 before the bad chunk came.
    # The status cannot change any more. The server hangs up, and the client
    # can tell that the response did not end properly.
    before = service.log().count(DISCONNECTED)
    sock = open_chunked_post(service.port)
    sock.sendall(chunk(RECORD))
    first = read_until(sock, REDACTED_RECORD)
    assert first.startswith(b"HTTP/1.1 200 ") and REDACTED_RECORD in first
    sock.sendall(b"zz\r\nsecond-secret\r\n")
    started = time.monotonic()
    rest = read_to_end(sock)  # returns when the server closes the connection
    sock.close()
    assert time.monotonic() - started < 5, "the server left the connection open"
    assert b"second-secret" not in rest
    assert b"HTTP/1.1" not in rest  # no second status line in the middle of a response
    assert not (first + rest).endswith(LAST_CHUNK)
    # The handler was told and stopped.
    assert service.wait_for_log(DISCONNECTED, count=before + 1)

    # The same exchange read by an HTTP client: it reports a broken response.
    sock = open_chunked_post(service.port)
    sock.sendall(chunk(RECORD))
    deadline = time.monotonic() + 10
    while REDACTED_RECORD not in sock.recv(65536, socket.MSG_PEEK):  # look without consuming
        assert time.monotonic() < deadline
        time.sleep(0.01)
    sock.sendall(b"zz\r\nsecond-secret\r\n")
    response = http.client.HTTPResponse(sock)
    response.begin()
    assert response.status == 200
    with pytest.raises(http.client.HTTPException):
        response.read()
    sock.close()

    assert request(service.port, "GET", "/healthz")[0] == 200


# --- streaming ----------------------------------------------------------------


def test_the_first_line_comes_back_while_the_request_is_still_open(service):
    sock = open_chunked_post(service.port)
    sock.sendall(chunk(RECORD))
    # The request is not finished: no final chunk has been sent.
    first = read_until(sock, REDACTED_RECORD)
    assert first.startswith(b"HTTP/1.1 200 ")
    assert REDACTED_RECORD in first

    sock.sendall(chunk(RECORD) + LAST_CHUNK)
    rest = read_until(sock, LAST_CHUNK)
    sock.close()
    assert (first + rest).count(REDACTED_RECORD) == 2
    assert rest.endswith(LAST_CHUNK)


def test_the_response_is_framed_so_that_the_client_knows_where_it_ends(service):
    # Two requests on one connection. The second can only be answered
    # correctly if the first response ended where the client expects it to.
    sock = socket.create_connection((HOST, service.port))
    sock.settimeout(10)
    sock.sendall(
        b"POST /redact HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%s" % (len(RECORD), RECORD)
        + b"GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
    )
    answer = read_to_end(sock)
    sock.close()

    first, separator, second = answer.partition(LAST_CHUNK)
    assert separator, "the first response has no final chunk"
    head = first.split(b"\r\n\r\n")[0].lower()
    assert head.startswith(b"http/1.1 200 ")
    assert b"transfer-encoding: chunked" in head and b"content-length" not in head
    assert REDACTED_RECORD in first
    assert second.startswith(b"HTTP/1.1 200 ") and second.endswith(b'{"status":"ok"}')


def test_output_arrives_while_a_large_request_is_still_being_sent(service):
    piece = SAMPLE * 6  # 300 lines, about 66 KB
    pieces = 150  # about 10 MB in all
    half = pieces // 2
    seen = {"lines": 0, "placeholders": 0, "bytes": 0, "tail": b""}
    marker = b'"redactor_error"'
    first_half_answered = threading.Event()
    waited = {}

    def body():
        for index in range(pieces):
            if index == half:
                # Hold the upload here until every line sent so far has been
                # answered. A service that kept its output until the end of
                # the request would never let this continue.
                waited["answered_in_time"] = first_half_answered.wait(timeout=60)
            yield piece

    def consume(data: bytes, progress: dict) -> None:
        seen["lines"] += data.count(b"\n")
        # A piece of the response can end in the middle of the marker, so the
        # end of the previous piece is counted together with this one.
        joined = seen["tail"] + data
        seen["placeholders"] += joined.count(marker)
        seen["tail"] = joined[-(len(marker) - 1) :]
        seen["bytes"] += len(data)
        if seen["lines"] >= 300 * half and not progress["done"]:
            first_half_answered.set()

    status = post_while_reading(service.port, body(), consume)

    assert status == 200
    assert waited["answered_in_time"], "no output for the first half while the second half was still unsent"
    assert seen["lines"] == 300 * pieces
    assert seen["placeholders"] == 18 * pieces  # three broken lines in each copy of the sample
    assert seen["bytes"] > len(piece) * pieces


def test_a_large_body_is_never_held_in_memory():
    piece = SAMPLE * 6
    pieces = 300  # about 20 MB in, a little more out
    received = 0

    def consume(data: bytes, progress: dict) -> None:
        nonlocal received
        received += len(data)

    with in_process_service() as port:
        post_while_reading(port, [piece], consume)  # warm up imports and caches
        received = 0
        tracemalloc.start()
        try:
            status = post_while_reading(port, (piece for _ in range(pieces)), consume)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

    assert status == 200
    assert received > 20_000_000
    # Server and client run in this process, and neither keeps the body. If
    # the service collected the request or the response, the peak would be
    # tens of megabytes.
    assert peak < 4_000_000, f"peak traced memory was {peak} bytes"


# --- several clients at once --------------------------------------------------


def test_simultaneous_requests_do_not_share_lines_numbers_or_counters(service):
    results = {}

    def client(number: int) -> None:
        lines = 20 + 10 * number
        broken = number + 2  # each client has its broken line somewhere else

        def body():
            for line in range(1, lines + 1):
                if line == broken:
                    yield b'{"client":%d,"password":"hunter2"\n' % number
                else:
                    yield b'{"client":%d,"n":%d,"password":"p"}\n' % (number, line)
                if line % 10 == 0:
                    time.sleep(0.02)  # keep the requests overlapping

        results[number] = request(service.port, "POST", "/redact", body=body())

    threads = [threading.Thread(target=client, args=(number,)) for number in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for number in range(8):
        lines, broken = 20 + 10 * number, number + 2
        status, _, body = results[number]
        assert status == 200
        answer = body.split(b"\n")[:-1]
        assert len(answer) == lines
        for line, text in enumerate(answer, start=1):
            if line == broken:
                # The line number is the client's own, not a shared count.
                assert text == b'{"redactor_error":"invalid_json","line":%d}' % broken
            else:
                assert text == b'{"client":%d,"n":%d,"password":"****"}' % (number, line)
        # One log line per request, with that request's counts.
        summary = (
            f"redactor: POST /redact: {lines} lines: {lines - 1} processed, 0 blank, 1 replaced "
            f"(invalid_json: 1); redactions: secret-fields: {lines - 1}\n"
        )
        assert service.wait_for_log(summary), summary


# --- clients that go away -----------------------------------------------------


def test_a_client_that_disconnects_while_sending(service):
    before = service.log().count(DISCONNECTED)
    sock = socket.create_connection((HOST, service.port))
    # The request promises 100,000 bytes and stops in the middle of a line.
    sock.sendall(b"POST /redact HTTP/1.1\r\nHost: test\r\nContent-Length: 100000\r\n\r\n" + RECORD + b'{"password":"cut-off-sec')
    time.sleep(0.2)
    sock.close()

    # The handler notices, stops, and logs what it had counted so far. The
    # unfinished line is not processed and not written anywhere.
    assert service.wait_for_log(DISCONNECTED, count=before + 1)
    assert "cut-off-sec" not in service.log()
    assert request(service.port, "POST", "/redact", body=RECORD)[2] == REDACTED_RECORD


def test_a_client_that_disconnects_while_receiving(service):
    before = service.log().count(DISCONNECTED)
    sock = open_chunked_post(service.port)
    stop_sending = threading.Event()

    def send() -> None:
        with contextlib.suppress(OSError):
            while not stop_sending.is_set():
                sock.sendall(chunk(SAMPLE * 6))

    sender = threading.Thread(target=send)
    sender.start()
    assert b"HTTP/1.1 200 " in read_until(sock, b"\r\n\r\n")
    sock.close()  # gone in the middle of the response, with the request still running
    stop_sending.set()
    sender.join(timeout=15)
    assert not sender.is_alive()

    # The request ends on the server side too: nothing is left running.
    assert service.wait_for_log(DISCONNECTED, count=before + 1)
    assert request(service.port, "GET", "/healthz")[0] == 200
    assert request(service.port, "POST", "/redact", body=RECORD)[2] == REDACTED_RECORD


# --- idempotency --------------------------------------------------------------


def test_the_service_is_idempotent(service):
    first = request(service.port, "POST", "/redact", body=SAMPLE)[2]
    second = request(service.port, "POST", "/redact", body=first)[2]
    assert second == first
    # The second request found nothing to redact and nothing to replace.
    assert service.wait_for_log("redactor: POST /redact: 50 lines: 48 processed, 2 blank, 0 replaced; redactions: none\n")


# --- the log ------------------------------------------------------------------


def test_each_request_is_logged_as_one_line_of_counts(service):
    request(service.port, "POST", "/redact", body=SAMPLE)
    assert service.wait_for_log(
        "redactor: POST /redact: 50 lines: 45 processed, 2 blank, 3 replaced (invalid_json: 3); "
        "redactions: auth-headers: 9, api-key-names: 8, secret-fields: 10, card-number-fields: 5, "
        "cvv-fields: 1, email: 31, jwt: 4, credit-card: 17, api-key-prefix: 2\n"
    )


def test_nothing_from_any_request_reaches_the_log(service):
    secrets = ["log-secret-body", "log-secret-broken", "log-secret-query", "log-secret-header",
               "log-secret-path", "log-secret-chunk", "log-secret-cut"]  # fmt: skip
    request(service.port, "POST", "/redact", body=b'{"password":"log-secret-body"}\n{"password":"log-secret-broken"\n')
    request(service.port, "POST", "/redact?api_key=log-secret-query", body=RECORD)
    request(service.port, "POST", "/redact", body=RECORD, headers={"Authorization": "Bearer log-secret-header"})
    request(service.port, "GET", "/log-secret-path")
    sock = open_chunked_post(service.port)
    sock.sendall(b"zz\r\nlog-secret-chunk\r\n")
    read_to_end(sock)
    sock.close()
    before = service.log().count(DISCONNECTED)
    sock = socket.create_connection((HOST, service.port))
    sock.sendall(b"POST /redact HTTP/1.1\r\nHost: test\r\nContent-Length: 500\r\n\r\n" + b'{"password":"log-secret-cut')
    time.sleep(0.2)
    sock.close()
    assert service.wait_for_log(DISCONNECTED, count=before + 1)

    log = service.log()
    for secret in secrets:
        assert secret not in log
    # Nothing from the earlier tests of this module either: they sent the
    # whole sample file many times.
    for fragment in ("hunter2", "dana", "@", "eyJ", "4111", "sk_live", "Bearer", "second-secret", "password"):
        assert fragment not in log
    assert "Traceback" not in log
    # What is there: uvicorn's own lines and one summary line per request.
    for line in log.splitlines():
        assert line.startswith(("INFO:", "WARNING:", "redactor: POST /redact")), line


def test_an_unexpected_error_ends_the_response_and_logs_no_exception_text(monkeypatch, capfd):
    class FailingStream(RedactionStream):
        def feed(self, data: bytes) -> bytes:
            if b"boom" in data:
                # Typical of Python: the message quotes the offending value.
                raise RuntimeError(f"cannot handle {data!r}")
            return super().feed(data)

    monkeypatch.setattr("redactor.server.RedactionStream", FailingStream)
    with in_process_service() as port:
        # Before any output: the server answers with a status of its own.
        status, _, body = request(port, "POST", "/redact", body=b'{"boom":"hunter2"}\n')
        assert status == 500
        assert b"hunter2" not in body and b"boom" not in body

        # After the first line was answered: the response is cut off, so the
        # client cannot mistake it for a complete one.
        sock = open_chunked_post(port)
        sock.sendall(chunk(RECORD))
        first = read_until(sock, REDACTED_RECORD)
        assert REDACTED_RECORD in first
        sock.sendall(chunk(b'{"boom":"hunter2"}\n') + chunk(RECORD) + LAST_CHUNK)
        rest = read_to_end(sock)
        sock.close()
        assert not (first + rest).endswith(LAST_CHUNK)
        assert (first + rest).count(REDACTED_RECORD) == 1  # nothing after the failure is sent
        assert b"boom" not in rest

    captured = capfd.readouterr()
    log = captured.out + captured.err
    assert log.count("(aborted: internal error)") == 2
    assert "hunter2" not in log and "boom" not in log
    assert "Traceback" not in log and "RuntimeError" not in log


# --- starting and stopping ----------------------------------------------------


@pytest.mark.parametrize("problem", ["missing", "invalid"])
def test_unusable_rules_stop_the_service_before_it_listens(tmp_path, problem):
    rules = tmp_path / "rules.yaml"
    if problem == "invalid":
        rules.write_text("version: 1\nvalue_rules:\n  - name: email\n    pattern: '@'\n    actoin: hash\n", encoding="utf-8")
    failing = Service(tmp_path, rules=rules)
    listened = False
    while failing.process.poll() is None:
        listened = listened or port_is_open(failing.port)
        time.sleep(0.01)
    assert failing.stop() == EXIT_USAGE
    assert not listened
    log = failing.log()
    assert "cannot load rules" in log
    assert "Uvicorn running" not in log and "Started server" not in log


def test_a_port_that_is_taken_gives_exit_code_1(service, tmp_path):
    second = Service(tmp_path, port=service.port)
    assert second.process.wait(timeout=30) == EXIT_IO_ERROR
    second.stop()
    assert "error while attempting to bind" in second.log()
    # The first service is not disturbed.
    assert request(service.port, "GET", "/healthz")[0] == 200


@pytest.mark.parametrize(
    "arguments",
    [
        ["--serve", "input.ndjson"],  # a file and a service at once
        ["--serve", "--addr", "8080"],
        ["--serve", "--addr", "localhost:"],
        ["--serve", "--addr", "localhost:http"],
        ["--serve", "--addr", "localhost:0"],
        ["--serve", "--addr", "localhost:70000"],
    ],
)
def test_invalid_service_arguments_are_usage_errors(arguments):
    process = subprocess.run([sys.executable, "-m", "redactor", *arguments], capture_output=True, cwd=ROOT, timeout=60)
    assert process.returncode == EXIT_USAGE
    assert process.stdout == b""


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (":8080", ("0.0.0.0", 8080)),  # every interface, as in the brief
        ("127.0.0.1:9000", ("127.0.0.1", 9000)),
        ("localhost:8080", ("localhost", 8080)),
        ("[::1]:8080", ("::1", 8080)),
    ],
)
def test_addr_is_parsed_into_host_and_port(text, expected):
    assert _build_parser().parse_args(["--serve", "--addr", text]).addr == expected


def test_the_default_address_is_port_8080_on_every_interface():
    assert _build_parser().parse_args(["--serve"]).addr == ("0.0.0.0", 8080)


def test_the_line_limit_is_not_a_service_option():
    process = subprocess.run(
        [sys.executable, "-m", "redactor", "--serve", "--addr", f"{HOST}:{free_port()}", "--max-line-bytes", "300"],
        capture_output=True,
        cwd=ROOT,
        timeout=60,
    )
    assert process.returncode == EXIT_USAGE
    assert process.stdout == b""
    assert b"unrecognized arguments: --max-line-bytes" in process.stderr


def test_a_stop_signal_lets_the_request_in_progress_finish(tmp_path):
    stopping = Service(tmp_path)
    try:
        assert stopping.wait_until_up(), stopping.log()
        sock = open_chunked_post(stopping.port)
        sock.sendall(chunk(RECORD))
        assert REDACTED_RECORD in read_until(sock, REDACTED_RECORD)

        stopping.signal_stop()
        assert stopping.wait_for_log("Shutting down")
        time.sleep(0.3)
        assert stopping.process.poll() is None  # still there: one request is open
        assert not port_is_open(stopping.port)  # but no new connections are accepted

        sock.sendall(chunk(RECORD) + LAST_CHUNK)
        rest = read_until(sock, LAST_CHUNK)
        sock.close()
        assert REDACTED_RECORD in rest and rest.endswith(LAST_CHUNK)

        assert stopping.process.wait(timeout=30) == EXIT_OK
        assert "Finished server process" in stopping.log()
    finally:
        stopping.stop()

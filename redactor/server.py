"""HTTP service mode: `redactor --serve --addr :8080 --rules rules.yaml`.

    POST /redact    NDJSON in, redacted NDJSON out, streamed in both directions
    GET  /healthz   200 while the service is up

The service adds no redaction logic. Each request gets its own Redactor and
RedactionStream, the same objects the command line uses, and this module only
moves bytes between the network and that stream.

The rules are loaded and validated by the caller before the application
exists, so a process that listens on a port always has usable rules.

Nothing from a request is ever logged: one line per request is written to
stderr, built from counters, fixed reason codes and rule names.
"""

import sys

import uvicorn
from fastapi import FastAPI
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from uvicorn.protocols.http.h11_impl import H11Protocol

from redactor.engine import Redactor
from redactor.rules import RuleSet
from redactor.stream import RedactionStream

# The request body is handed to the stream in pieces of at most this size,
# whatever size the server delivers. See RedactionStream.feed: the caller
# bounds the memory by the size of the chunks it passes.
_CHUNK_BYTES = 64 * 1024

_RESPONSE_HEADERS = [(b"content-type", b"application/x-ndjson")]


def create_app(rules: RuleSet, max_line_bytes: int) -> FastAPI:
    """Build the web application around an already validated rule set.

    Args:
        rules: Shared by all requests. A RuleSet is read-only.
        max_line_bytes: Longest NDJSON line that is still processed.
    """
    app = FastAPI(
        title="API Traffic Redactor",
        # No generated API schema, and with it no documentation pages: the
        # service exposes exactly the two paths below.
        openapi_url=None,
        # FastAPI can export traces that include the request URL and its
        # query string. A redaction service must not send request data
        # anywhere, even if a telemetry collector is configured around it.
        telemetry={"tracing": False, "metrics": False, "logs": False},
    )

    @app.post("/redact")
    async def redact() -> Response:
        return RedactionResponse(rules, max_line_bytes)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        # The process does not start without valid rules, so "it answers"
        # already means "the rules are loaded".
        return {"status": "ok"}

    return app


class RedactionResponse(Response):
    """Answers one POST /redact: reads the body as it arrives and sends the redacted lines at once.

    A response object is the ASGI application for its request, called with
    `receive` (messages from the client) and `send` (messages to the client).
    This class uses those two directly, with the message types of the ASGI
    HTTP specification, so that reading and writing can alternate:

        receive a piece of the body -> feed it to the stream -> send the output

    The stock StreamingResponse cannot be used for this. It watches for a
    disconnect by reading `receive` itself while it sends, and drops every
    message that is not a disconnect, including the request body.

    No Content-Length is sent, because the size is unknown in advance. The
    server then frames the body with chunked transfer encoding, and the final
    empty chunk tells the client that the response is complete.
    """

    def __init__(self, rules: RuleSet, max_line_bytes: int):
        super().__init__()
        self._rules = rules
        self._max_line_bytes = max_line_bytes

    async def __call__(self, scope, receive, send) -> None:
        # One Redactor and one stream per request: nothing a client sends can
        # reach another client's partial line, line numbers or counters.
        redactor = Redactor(self._rules)
        stream = RedactionStream(redactor, self._max_line_bytes)
        started = False
        # Stays in the log line unless the request runs to its end, which
        # also covers a request cancelled by a server shutdown.
        problem = " (interrupted)"

        async def send_output(data: bytes) -> None:
            # The status line goes out with the first output, not before. If
            # the request turns out to be malformed HTTP before any output
            # exists, the server can still answer 400 instead.
            nonlocal started
            if not started:
                started = True
                await send({"type": "http.response.start", "status": 200, "headers": _RESPONSE_HEADERS})
            await send({"type": "http.response.body", "body": data, "more_body": True})

        try:
            more_body = True
            while more_body:
                message = await receive()
                if message["type"] == "http.disconnect":
                    # The connection is gone, or the server closed it after a
                    # protocol error. Stop reading and redacting.
                    problem = " (connection closed before the request ended)"
                    return
                body = message.get("body", b"")
                more_body = message.get("more_body", False)
                for start in range(0, len(body), _CHUNK_BYTES):
                    # The engine is ordinary blocking code. A worker thread
                    # runs it, so the event loop can serve other connections
                    # between its steps.
                    output = await run_in_threadpool(stream.feed, body[start : start + _CHUNK_BYTES])
                    if output:
                        await send_output(output)

            await send_output(stream.finish())
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            problem = ""
        except Exception:  # noqa: BLE001 - deliberate catch-all, see below
            # Neither the exception nor a traceback is written anywhere: both
            # can quote request data. Returning without the final message
            # makes the server close the connection, so the client sees a
            # response that was cut off, never one that looks complete.
            problem = " (aborted: internal error)"
        finally:
            _log_request(stream, redactor, problem)


class _HttpProtocol(H11Protocol):
    """uvicorn's HTTP/1.1 protocol with one correction for streamed responses.

    When a request turns out to be malformed, uvicorn answers 400. If the
    body becomes malformed after our response has started (a bad chunk in
    the middle of an upload), a second status line cannot be sent. uvicorn
    0.54 tries anyway: the attempt raises, a traceback lands in the log and,
    on Windows, the connection stays open with the client waiting forever.

    Here the connection is closed instead. The client sees a response that
    was cut off, and the handler is told that the client is gone.
    """

    def send_400_response(self, msg: str) -> None:
        try:
            super().send_400_response(msg)
        except Exception:  # noqa: BLE001 - whatever went wrong, the answer is to hang up
            self.transport.close()


def run(rules: RuleSet, host: str, port: int, max_line_bytes: int) -> None:
    """Serve until the process is told to stop (Ctrl+C, SIGTERM).

    uvicorn then stops accepting connections, lets the requests in progress
    finish, and this function returns. If the server cannot start, for
    example because the port is taken, uvicorn logs the reason and raises
    SystemExit.
    """
    config = uvicorn.Config(
        create_app(rules, max_line_bytes),
        host=host,
        port=port,
        http=_HttpProtocol,
        # uvicorn's access log prints the request URL, and a query string can
        # hold a secret. _log_request writes one line per request instead.
        access_log=False,
    )
    uvicorn.Server(config).run()


def _log_request(stream: RedactionStream, redactor: Redactor, problem: str) -> None:
    """Write the summary of one request to stderr: counts only, on a single line.

    One line per request, so that the lines of simultaneous requests cannot
    interleave. The URL is not logged: a query string may hold a secret.
    """
    stats = stream.stats
    summary = (
        f"{stats.lines} lines: {stats.processed} processed, {stats.blank} blank, "
        f"{stats.replaced.total()} replaced"
    )
    if stats.replaced:
        reasons = ", ".join(f"{reason}: {count}" for reason, count in sorted(stats.replaced.items()))
        summary += f" ({reasons})"
    redactions = ", ".join(f"{name}: {count}" for name, count in redactor.counts.items() if count)
    print(
        f"redactor: POST /redact{problem}: {summary}; redactions: {redactions or 'none'}",
        file=sys.stderr,
        flush=True,
    )

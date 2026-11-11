"""Command-line interface.

    redactor [--rules rules.yaml] [input-file]          redact a file or stdin
    redactor --serve --addr :8080 --rules rules.yaml    run as an HTTP service

File mode reads NDJSON from a file or from stdin and writes the redacted
NDJSON to stdout as it goes. When the input is finished, one summary is
printed to stderr: how many lines were read, processed, blank and replaced,
the replaced ones per reason, and the number of redactions per rule.

stdout carries data only. stderr never carries input data: the summary is
built from counters, fixed reason codes and rule names. A record that could
not be processed is not reported one by one; its placeholder on stdout holds
the line number and the reason.

Service mode is described in server.py. In both modes the rules are loaded
first, and nothing is read or served if they are unusable.

Exit codes:
    0  every record was processed, or the service was stopped
    1  input/output failure (file not found, output closed, port in use, ...)
    2  invalid arguments, or the rules could not be loaded
    3  finished, but at least one record was replaced by a placeholder
"""

import argparse
import signal
import sys

from redactor.engine import Redactor
from redactor.rules import RulesError, RuleSet, load_rules
from redactor.stream import DEFAULT_MAX_LINE_BYTES, RedactionStream

EXIT_OK = 0
EXIT_IO_ERROR = 1
EXIT_USAGE = 2
EXIT_RECORDS_REPLACED = 3

# How much input is read, redacted and written at a time. This bounds the
# memory of a run: see RedactionStream.feed.
_CHUNK_BYTES = 64 * 1024


def main(argv: list[str] | None = None) -> int:
    """Run the command-line tool and return its exit code.

    Args:
        argv: Arguments without the program name. Defaults to sys.argv[1:].
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.serve and args.input is not None:
        parser.error("an input file cannot be combined with --serve")

    # The rules are loaded before any input is opened and before any port is
    # listened on. If they are unusable the program stops here, so nothing
    # can pass through unredacted.
    try:
        rules = load_rules(args.rules)
    except RulesError as error:
        _say(f"cannot load rules: {error}")
        return EXIT_USAGE

    if args.serve:
        return _serve(rules, args.addr, args.max_line_bytes)

    redactor = Redactor(rules)
    stream = RedactionStream(redactor, args.max_line_bytes)
    try:
        _copy(args.input, stream)
    except OSError as error:
        # An OSError message names the file and the system error, never the data.
        _say(f"input/output error: {error}")
        # If the output is what failed (`redactor big.ndjson | head`: the
        # reader went away), Python would try to flush stdout again at exit,
        # print that second error and turn the exit code into 120. Closing
        # stdout here, and ignoring that it fails once more, prevents both.
        try:
            sys.stdout.close()
        except OSError:
            pass
        return EXIT_IO_ERROR

    # _copy has flushed stdout, so the summary always follows the last record.
    _print_summary(stream, redactor)
    return EXIT_RECORDS_REPLACED if stream.stats.replaced else EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redactor",
        description="Redact sensitive data from NDJSON API traffic logs.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        metavar="input-file",
        help="NDJSON file to read (default: standard input)",
    )
    parser.add_argument(
        "--rules",
        default="rules.yaml",
        help="rules file (default: %(default)s)",
    )
    parser.add_argument(
        "--max-line-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_LINE_BYTES,
        metavar="N",
        help="longest line that is processed; longer lines are replaced "
        "by a placeholder (default: %(default)s)",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="run as an HTTP service (POST /redact, GET /healthz) instead of reading input",
    )
    parser.add_argument(
        "--addr",
        type=_address,
        default=("0.0.0.0", 8080),
        metavar="HOST:PORT",
        help="address the service listens on; ':8080' means every interface (default: :8080)",
    )
    return parser


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise argparse.ArgumentTypeError("must be a whole number greater than 0")
    return value


def _address(text: str) -> tuple[str, int]:
    """Parse `HOST:PORT`, or `:PORT` for every interface, into (host, port)."""
    host, colon, port = text.rpartition(":")
    if not colon or not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError("must be HOST:PORT or :PORT, with a port from 1 to 65535")
    # An IPv6 address is written in brackets, as in [::1]:8080.
    return host.strip("[]") or "0.0.0.0", int(port)


def _serve(rules: RuleSet, address: tuple[str, int], max_line_bytes: int) -> int:
    """Run the HTTP service until it is stopped; return the exit code."""
    # Imported here so that plain file mode does not load the web framework.
    from redactor import server

    # Once uvicorn has shut down after a signal, it sends itself the same
    # signal again so that the handlers from before take over. The default
    # handlers would end the process with a failure status (on Windows with
    # code 3, which means something else here). With a handler that does
    # nothing, server.run() simply returns and the exit code is 0.
    for name in ("SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: None)

    host, port = address
    try:
        server.run(rules, host, port, max_line_bytes)
    except KeyboardInterrupt:
        pass
    except SystemExit:
        # uvicorn has logged why it could not start (port in use, say) and
        # exits with its own code, 3, which means something else here.
        return EXIT_IO_ERROR
    return EXIT_OK


def _copy(input_path: str | None, stream: RedactionStream) -> None:
    """Move the input through `stream` to stdout, one chunk at a time.

    Both ends are binary. In text mode Python on Windows would turn every
    line feed into CR LF and decode the input with the system code page.
    """
    source = sys.stdin.buffer if input_path is None else open(input_path, "rb")
    output = sys.stdout.buffer
    try:
        # read1() returns as soon as some data is available, so a slow pipe
        # is processed as it arrives instead of waiting for a full chunk.
        while chunk := source.read1(_CHUNK_BYTES):
            output.write(stream.feed(chunk))
            output.flush()
        output.write(stream.finish())
        output.flush()
    finally:
        if input_path is not None:
            source.close()


def _print_summary(stream: RedactionStream, redactor: Redactor) -> None:
    """Print the end-of-run summary to stderr.

    Everything in it comes from counters: no message and no list of failed
    lines is kept during the run, so a file full of broken lines costs no
    extra memory and adds no lines to stderr.
    """
    stats = stream.stats
    totals = (
        f"{stats.lines} lines: {stats.processed} processed, {stats.blank} blank, "
        f"{stats.replaced.total()} replaced"
    )
    if stats.replaced:
        reasons = ", ".join(f"{reason}: {count}" for reason, count in sorted(stats.replaced.items()))
        totals += f" ({reasons})"
    _say(totals)
    _say("redactions by rule:")
    width = max(len(name) for name in redactor.counts)
    for name, count in redactor.counts.items():
        # Plain print: these lines are a table under the header above.
        print(f"  {name:<{width}}  {count}", file=sys.stderr)


def _say(message: str) -> None:
    print(f"redactor: {message}", file=sys.stderr)

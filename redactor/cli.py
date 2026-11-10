"""Command-line interface: `redactor [--rules rules.yaml] [input-file]`.

Reads NDJSON from a file or from stdin and writes the redacted NDJSON to
stdout as it goes. When the input is finished, one summary is printed to
stderr: how many lines were read, processed, blank and replaced, the replaced
ones per reason, and the number of redactions per rule.

stdout carries data only. stderr never carries input data: the summary is
built from counters, fixed reason codes and rule names. A record that could
not be processed is not reported one by one; its placeholder on stdout holds
the line number and the reason.

Exit codes:
    0  every record was processed
    1  input/output failure (file not found, output closed, ...)
    2  invalid arguments, or the rules could not be loaded
    3  finished, but at least one record was replaced by a placeholder
"""

import argparse
import os
import sys

from redactor.engine import Redactor
from redactor.rules import RulesError, load_rules
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
    args = _build_parser().parse_args(argv)

    # The rules are loaded before any input is opened. If they are unusable
    # the program stops here, so nothing can pass through unredacted.
    try:
        rules = load_rules(args.rules)
    except RulesError as error:
        _say(f"cannot load rules: {error}")
        return EXIT_USAGE

    redactor = Redactor(rules)
    stream = RedactionStream(redactor, args.max_line_bytes)
    try:
        _copy(args.input, stream)
    except OSError as error:
        # An OSError message names the file and the system error, never the data.
        _say(f"input/output error: {error}")
        _silence_stdout()
        return EXIT_IO_ERROR

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
    return parser


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise argparse.ArgumentTypeError("must be a whole number greater than 0")
    return value


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


def _silence_stdout() -> None:
    """Point stdout at the null device after a failed write.

    When the reader of a pipe has gone away (`redactor big.ndjson | head`),
    Python would try to flush stdout once more at exit and print a second,
    confusing error. This is the remedy the Python documentation recommends.
    """
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        pass

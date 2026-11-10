"""Memory-bounded NDJSON streaming: bytes in, redacted bytes out.

RedactionStream turns a stream of bytes, delivered in chunks of any size, into
lines, hands each line to the engine and returns the output. It is the same
object for a file, for stdin and for an HTTP request body: the caller only
moves bytes.

Guarantees:
  * Bounded memory. Only the line currently being assembled is held, and
    never more than `max_line_bytes` of it.
  * One output line for every input line, in the same order. Output line N
    always corresponds to input line N.
  * Fail closed. A line that cannot be redacted safely is replaced by a
    placeholder that contains nothing from the input, and processing goes on
    with the next line.

Cost: the stream itself does a constant amount of work per input byte (find
the newline, copy the line). The total run time is not a property of this
module: it also depends on how many rules there are and on how their regular
expressions behave on the data.
"""

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

from redactor.engine import RecordError, Redactor

DEFAULT_MAX_LINE_BYTES = 1024 * 1024

# Reasons a line is replaced that only this layer can detect. The engine adds
# its own (invalid_json, invalid_embedded_json, too_deep).
REASON_INVALID_UTF8 = "invalid_utf8"
REASON_LINE_TOO_LONG = "line_too_long"
REASON_INTERNAL_ERROR = "internal_error"

_UTF8_BOM = b"\xef\xbb\xbf"
_JSON_WHITESPACE = b" \t\r\n"


@dataclass
class StreamStats:
    """What happened to the lines of one stream.

    Attributes:
        lines: Input lines seen so far.
        blank: Lines that held only whitespace. They are passed on as empty lines.
        replaced: Lines replaced by a placeholder, counted per reason code.
    """

    lines: int = 0
    blank: int = 0
    replaced: Counter[str] = field(default_factory=Counter)

    @property
    def processed(self) -> int:
        """Lines that went through the engine and were written as records."""
        return self.lines - self.blank - self.replaced.total()


class RedactionStream:
    """Redacts NDJSON incrementally.

    Use it like zlib's compressobj: call feed() with each chunk of input and
    write what it returns, then call finish() once and write that too.

    Args:
        redactor: The engine. Its `counts` hold the redactions per rule.
        max_line_bytes: Longest line, in bytes without its newline, that is
            still processed. A longer line is replaced by a placeholder.
        report: Optional callback `report(line_number, reason)` invoked for
            every replaced line. It receives nothing from the input.

    Attributes:
        stats: Running StreamStats for this stream.
    """

    def __init__(
        self,
        redactor: Redactor,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        report: Callable[[int, str], None] | None = None,
    ):
        if max_line_bytes < 1:
            raise ValueError("max_line_bytes must be at least 1")
        self._redactor = redactor
        self._max_line_bytes = max_line_bytes
        self._report = report
        # The current line, as far as it has arrived. A bytearray grows in
        # place, so a line delivered one byte at a time still costs linear
        # time; joining bytes objects would copy the line on every chunk.
        self._pending = bytearray()
        # True while skipping the rest of a line that exceeded the limit.
        self._discarding = False
        self.stats = StreamStats()

    def feed(self, chunk: bytes) -> bytes:
        """Take the next chunk of input; return the output for every line it completed.

        A chunk may end anywhere, including in the middle of a line or of a
        multi-byte character. The unfinished part is kept for the next call.
        """
        output = []
        start = 0
        while (newline := chunk.find(b"\n", start)) != -1:
            self._hold(chunk[start:newline])
            output.append(self._end_line())
            start = newline + 1
        self._hold(chunk[start:])
        return b"".join(output)

    def finish(self) -> bytes:
        """Return the output for a last line that did not end with a newline.

        Call once, after the last feed(). Returns b"" if the input ended with
        a newline (or was empty).
        """
        if not self._pending and not self._discarding:
            return b""
        return self._end_line()

    def _hold(self, piece: bytes) -> None:
        """Add `piece` to the current line, unless the line is over the limit."""
        if self._discarding:
            return
        if len(self._pending) + len(piece) > self._max_line_bytes:
            # Stop buffering. Whatever else belongs to this line is dropped as
            # it arrives, so even a single endless line needs no more memory.
            self._pending.clear()
            self._discarding = True
            return
        self._pending += piece

    def _end_line(self) -> bytes:
        """Process the line that just ended and return its output line."""
        self.stats.lines += 1
        number = self.stats.lines
        if self._discarding:
            self._discarding = False
            return self._placeholder(number, REASON_LINE_TOO_LONG) + b"\n"
        line = bytes(self._pending)
        self._pending.clear()
        return self._redact_line(number, line) + b"\n"

    def _redact_line(self, number: int, line: bytes) -> bytes:
        """Return the output for one complete input line, without its newline."""
        # Normalisation. Each step is stable on its own output, so running the
        # tool again on what it wrote changes nothing: there is no BOM left to
        # strip, no "\r" left to drop, and a blank line is already empty.
        if number == 1 and line.startswith(_UTF8_BOM):
            # Some Windows tools put a byte order mark at the start of a file.
            # Left in place it would make the first record invalid JSON.
            line = line[len(_UTF8_BOM) :]
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line.strip(_JSON_WHITESPACE):
            self.stats.blank += 1
            return b""

        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            return self._placeholder(number, REASON_INVALID_UTF8)
        try:
            redacted = self._redactor.redact(text)
        except RecordError as error:
            return self._placeholder(number, error.reason)
        except Exception:  # noqa: BLE001 - deliberate catch-all, see below
            # A bug in the engine must neither stop the stream nor let the
            # line through. The exception is deliberately not logged: Python
            # error messages often quote the value that caused them.
            return self._placeholder(number, REASON_INTERNAL_ERROR)

        if redacted is text:
            # Nothing was redacted: write the bytes exactly as they came.
            return line
        return redacted.encode("utf-8")

    def _placeholder(self, number: int, reason: str) -> bytes:
        """Record that line `number` was replaced and return what is written instead.

        The placeholder is a valid JSON record built only from the line number
        and a fixed reason code, so the output stays valid NDJSON, the loss is
        visible to whoever reads it, and nothing from the line can leak.
        """
        self.stats.replaced[reason] += 1
        if self._report is not None:
            self._report(number, reason)
        return b'{"redactor_error":"%s","line":%d}' % (reason.encode("ascii"), number)

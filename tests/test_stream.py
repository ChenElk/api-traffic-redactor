"""Unit tests for the streaming layer (bytes in, redacted bytes out)."""

import json
import random
import tracemalloc
from collections import Counter
from pathlib import Path

import pytest

from redactor.engine import Redactor
from redactor.rules import load_rules
from redactor.stream import (
    DEFAULT_MAX_LINE_BYTES,
    REASON_INTERNAL_ERROR,
    REASON_INVALID_UTF8,
    REASON_LINE_TOO_LONG,
    RedactionStream,
)

ROOT = Path(__file__).resolve().parent.parent
PROVIDED = load_rules(ROOT / "rules.yaml")
SAMPLE = (ROOT / "input.ndjson").read_bytes()
BOM = b"\xef\xbb\xbf"


def run_stream(data: bytes, chunk_size: int | None = None, **options):
    """Feed `data` through a new stream in chunks; return (output, stream)."""
    stream = RedactionStream(Redactor(PROVIDED), **options)
    step = chunk_size or max(len(data), 1)
    output = [stream.feed(data[start : start + step]) for start in range(0, len(data), step)]
    output.append(stream.finish())
    return b"".join(output), stream


def output_lines(output: bytes) -> list[bytes]:
    """The lines of an output that must end with a newline."""
    assert output.endswith(b"\n")
    return output[:-1].split(b"\n")


def placeholder(reason: str, line: int) -> bytes:
    return b'{"redactor_error":"%s","line":%d}' % (reason.encode(), line)


def json_line_of_length(length: int) -> bytes:
    """A valid JSON record that is exactly `length` bytes long.

    The filler is spaces on purpose. A megabyte of letters would send the
    provided e-mail pattern into quadratic backtracking (minutes for one
    line); that is a property of the pattern, not of the stream under test.
    """
    return b'{"k":"' + b" " * (length - 8) + b'"}'


EXPECTED_SAMPLE_OUTPUT, _ = run_stream(SAMPLE)


# --- chunking -----------------------------------------------------------------


@pytest.mark.parametrize("chunk_size", [1, 2, 3, 7, 64, 1000, 4096])
def test_output_does_not_depend_on_the_chunk_size(chunk_size):
    # One byte at a time splits every line, every multi-byte character and
    # every escape sequence across calls.
    output, _ = run_stream(SAMPLE, chunk_size)
    assert output == EXPECTED_SAMPLE_OUTPUT


@pytest.mark.parametrize("seed", range(5))
def test_output_does_not_depend_on_where_chunks_are_cut(seed):
    generator = random.Random(seed)
    stream = RedactionStream(Redactor(PROVIDED))
    output = []
    position = 0
    while position < len(SAMPLE):
        size = generator.choice([1, 2, 5, 17, 100, 700, 3000])
        output.append(stream.feed(SAMPLE[position : position + size]))
        position += size
    output.append(stream.finish())
    assert b"".join(output) == EXPECTED_SAMPLE_OUTPUT


def test_an_empty_chunk_is_harmless():
    stream = RedactionStream(Redactor(PROVIDED))
    assert stream.feed(b"") == b""
    assert stream.feed(b'{"a":1}') == b""
    assert stream.feed(b"") == b""
    assert stream.feed(b"\n") == b'{"a":1}\n'
    assert stream.finish() == b""


# --- one output line per input line, in order ---------------------------------


def test_the_sample_keeps_its_line_count_and_line_numbers():
    lines_in = SAMPLE[:-1].split(b"\n")
    lines_out = output_lines(EXPECTED_SAMPLE_OUTPUT)
    assert len(lines_out) == len(lines_in) == 50

    # Blank lines stay blank, so every later line keeps its number.
    assert lines_out[19 - 1] == b""
    assert lines_out[22 - 1] == b""
    # The three lines that are not valid JSON become placeholders in place.
    assert lines_out[20 - 1] == placeholder("invalid_json", 20)
    assert lines_out[21 - 1] == placeholder("invalid_json", 21)
    assert lines_out[50 - 1] == placeholder("invalid_json", 50)


@pytest.mark.parametrize("line_number", [4, 17, 18, 23, 37, 48, 49])
def test_a_line_with_nothing_to_redact_is_written_byte_for_byte(line_number):
    lines_in = SAMPLE.split(b"\n")
    lines_out = EXPECTED_SAMPLE_OUTPUT.split(b"\n")
    assert lines_out[line_number - 1] == lines_in[line_number - 1]


def test_order_is_preserved():
    records = [b'{"n":%d,"password":"p%d"}' % (n, n) for n in range(500)]
    output, _ = run_stream(b"\n".join(records) + b"\n", chunk_size=333)
    numbers = [json.loads(line)["n"] for line in output_lines(output)]
    assert numbers == list(range(500))


def test_stats_describe_the_stream():
    _, stream = run_stream(SAMPLE)
    assert stream.stats.lines == 50
    assert stream.stats.blank == 2
    assert stream.stats.replaced == Counter({"invalid_json": 3})
    assert stream.stats.processed == 45


# --- a line that cannot be processed does not stop the others -----------------


def test_a_broken_line_between_two_good_ones_is_isolated():
    data = (
        b'{"body":{"password":"first"}}\n'
        b'{"body":{"password":"hunter2"}\n'  # one closing brace short
        b'{"body":{"password":"third"}}\n'
    )
    output, stream = run_stream(data)
    assert output_lines(output) == [
        b'{"body":{"password":"****"}}',
        placeholder("invalid_json", 2),
        b'{"body":{"password":"****"}}',
    ]
    assert b"hunter2" not in output
    assert stream.stats.replaced == Counter({"invalid_json": 1})


def test_reasons_from_the_engine_are_passed_into_the_placeholder():
    broken_embedded = json.dumps({"body": '{"password":"hunter2"'}).encode()
    too_deep = b"[" * 5_000 + b"]" * 5_000
    output, _ = run_stream(broken_embedded + b"\n" + too_deep + b"\n")
    assert output_lines(output) == [
        placeholder("invalid_embedded_json", 1),
        placeholder("too_deep", 2),
    ]


def test_a_placeholder_is_valid_json_with_only_a_code_and_a_line_number():
    output, _ = run_stream(b"not json at all, from erin@example.com\n")
    record = json.loads(output)
    assert record == {"redactor_error": "invalid_json", "line": 1}


def test_invalid_utf8_is_replaced():
    data = b'{"a":1}\n{"name":"caf\xe9"}\n{"b":2}\n'  # 0xE9 alone is Latin-1, not UTF-8
    output, _ = run_stream(data)
    assert output_lines(output) == [b'{"a":1}', placeholder(REASON_INVALID_UTF8, 2), b'{"b":2}']


def test_an_unexpected_error_in_the_engine_is_contained():
    class ExplodingRedactor:
        counts = Counter()

        def redact(self, line):
            if "boom" in line:
                # Typical of Python: the message quotes the offending value.
                raise RuntimeError(f"cannot handle {line!r}")
            return line

    reports = []
    stream = RedactionStream(ExplodingRedactor(), report=lambda *event: reports.append(event))
    output = stream.feed(b'{"a":1}\n{"boom":"hunter2"}\n{"b":2}\n') + stream.finish()

    assert output_lines(output) == [b'{"a":1}', placeholder(REASON_INTERNAL_ERROR, 2), b'{"b":2}']
    assert b"hunter2" not in output
    assert reports == [(2, REASON_INTERNAL_ERROR)]


def test_every_replaced_line_is_reported_without_its_content():
    reports = []
    run_stream(SAMPLE, report=lambda number, reason: reports.append((number, reason)))
    # Blank lines are not problems and are not reported.
    assert reports == [(20, "invalid_json"), (21, "invalid_json"), (50, "invalid_json")]


# --- line endings, blank lines, BOM, last line --------------------------------


def test_a_last_line_without_a_newline_is_processed_and_terminated():
    stream = RedactionStream(Redactor(PROVIDED))
    assert stream.feed(b'{"a":1}\n{"password":"x"}') == b'{"a":1}\n'
    assert stream.finish() == b'{"password":"****"}\n'


def test_empty_input_gives_empty_output():
    output, stream = run_stream(b"")
    assert output == b""
    assert stream.stats.lines == 0


def test_crlf_input_is_written_with_lf():
    output, _ = run_stream(SAMPLE.replace(b"\n", b"\r\n"), chunk_size=5)
    assert b"\r" not in output
    assert output == EXPECTED_SAMPLE_OUTPUT


def test_whitespace_only_lines_become_empty_lines():
    output, stream = run_stream(b'\n   \n\t\r\n{"a":1}\n')
    assert output == b'\n\n\n{"a":1}\n'
    assert stream.stats.blank == 3
    assert not stream.stats.replaced


@pytest.mark.parametrize("chunk_size", [None, 1])
def test_a_byte_order_mark_at_the_start_is_dropped(chunk_size):
    output, _ = run_stream(BOM + SAMPLE, chunk_size)
    assert output == EXPECTED_SAMPLE_OUTPUT


def test_only_a_leading_byte_order_mark_is_dropped():
    output, _ = run_stream(b'{"a":1}\n' + BOM + b'{"b":2}\n')
    assert output_lines(output) == [b'{"a":1}', placeholder("invalid_json", 2)]


# --- lines over the size limit ------------------------------------------------


@pytest.mark.parametrize("chunk_size", [None, 1, 7])
def test_a_line_over_the_limit_is_replaced_and_the_limit_itself_is_allowed(chunk_size):
    at_limit = json_line_of_length(40)
    over_limit = json_line_of_length(41)
    data = at_limit + b"\n" + over_limit + b"\n" + b'{"password":"x"}\n'
    output, stream = run_stream(data, chunk_size, max_line_bytes=40)
    assert output_lines(output) == [
        at_limit,
        placeholder(REASON_LINE_TOO_LONG, 2),
        b'{"password":"****"}',
    ]
    assert stream.stats.replaced == Counter({REASON_LINE_TOO_LONG: 1})


def test_an_oversized_last_line_without_a_newline_is_replaced():
    output, _ = run_stream(b'{"a":1}\n' + b"x" * 100, max_line_bytes=40)
    assert output_lines(output) == [b'{"a":1}', placeholder(REASON_LINE_TOO_LONG, 2)]


def test_an_endless_line_is_never_held_in_memory():
    limit = 1000
    stream = RedactionStream(Redactor(PROVIDED), max_line_bytes=limit)
    chunk = b"x" * 4096
    for _ in range(1280):  # about 5 MB without a single newline
        assert stream.feed(chunk) == b""
        assert len(stream._pending) <= limit
    # The line ends at last; the record after it is processed normally.
    output = stream.feed(b'\n{"password":"x"}\n') + stream.finish()
    assert output_lines(output) == [
        placeholder(REASON_LINE_TOO_LONG, 1),
        b'{"password":"****"}',
    ]


def test_the_default_limit_is_one_mebibyte():
    assert DEFAULT_MAX_LINE_BYTES == 1024 * 1024
    _, stream = run_stream(json_line_of_length(DEFAULT_MAX_LINE_BYTES) + b"\n")
    assert not stream.stats.replaced
    _, stream = run_stream(json_line_of_length(DEFAULT_MAX_LINE_BYTES + 1) + b"\n")
    assert stream.stats.replaced == Counter({REASON_LINE_TOO_LONG: 1})


def test_a_limit_below_one_byte_is_rejected():
    with pytest.raises(ValueError):
        RedactionStream(Redactor(PROVIDED), max_line_bytes=0)


# --- encoding -----------------------------------------------------------------


def test_a_rewritten_line_is_written_as_utf8():
    line = '{"city":"Zürich","note":"名前 😀","password":"x"}'
    output, _ = run_stream(line.encode("utf-8") + b"\n")
    assert output.decode("utf-8") == '{"city":"Zürich","note":"名前 😀","password":"****"}\n'


def test_a_lone_surrogate_in_a_rewritten_line_does_not_break_the_stream():
    # \ud83d is half of an emoji: legal in JSON, impossible in UTF-8.
    output, stream = run_stream(b'{"odd":"\\ud83d","password":"x"}\n{"b":2}\n')
    assert output_lines(output) == [b'{"odd":"\\ud83d","password":"****"}', b'{"b":2}']
    assert not stream.stats.replaced


# --- idempotency of the whole file --------------------------------------------


def test_running_the_stream_on_its_own_output_changes_nothing():
    second, stream = run_stream(EXPECTED_SAMPLE_OUTPUT)
    assert second == EXPECTED_SAMPLE_OUTPUT
    assert sum(stream._redactor.counts.values()) == 0
    # The placeholders of the first run are ordinary valid records now.
    assert not stream.stats.replaced
    assert stream.stats.blank == 2


def test_normalisation_does_not_break_idempotency():
    # Same content with a BOM, CRLF line endings and no final newline.
    messy = BOM + SAMPLE.replace(b"\n", b"\r\n")[:-2]
    first, _ = run_stream(messy, chunk_size=13)
    assert first == EXPECTED_SAMPLE_OUTPUT
    second, _ = run_stream(first)
    assert second == first


# --- memory -------------------------------------------------------------------


def test_memory_stays_bounded_while_the_input_grows():
    # About 3.3 MB of input, fed in 64 KiB chunks and never stored. If the
    # stream kept what it has read, or what it has written, the peak would
    # grow with the input. It must stay far below the size of the input.
    repetitions = 300
    stream = RedactionStream(Redactor(PROVIDED))
    stream.feed(SAMPLE)  # warm up caches (compiled patterns, json internals)

    tracemalloc.start()
    try:
        total_in = total_out = 0
        for _ in range(repetitions):
            for start in range(0, len(SAMPLE), 65536):
                chunk = SAMPLE[start : start + 65536]
                total_in += len(chunk)
                total_out += len(stream.feed(chunk))
        total_out += len(stream.finish())
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert total_in > 3_000_000 and total_out > 3_000_000
    assert stream.stats.lines == 50 * (repetitions + 1)
    assert peak < 1_000_000, f"peak traced memory was {peak} bytes"

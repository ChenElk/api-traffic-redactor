"""End-to-end tests of the command-line tool, run as a real process.

Each test starts `python -m redactor` with real pipes, so what is checked is
what a shell would see: the exact bytes on stdout, the text on stderr and the
exit code.
"""

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from redactor.actions import sha256_digest
from redactor.cli import EXIT_IO_ERROR, EXIT_OK, EXIT_RECORDS_REPLACED, EXIT_USAGE
from redactor.engine import Redactor
from redactor.rules import load_rules
from redactor.stream import DEFAULT_MAX_LINE_BYTES, RedactionStream

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = (ROOT / "input.ndjson").read_bytes()
ALTERNATIVE_RULES = ROOT / "tests" / "data" / "alt_rules.yaml"

# Strings that appear in input.ndjson and must never reach stderr.
INPUT_FRAGMENTS = [
    "hunter2", "abc123", "example", "@", "eyJ", "4111", "trunc", "erin",
    "sk_live", "Bearer", "upstream", "/v1/",
]


def run_cli(*args: str, stdin: bytes = b"", cwd: Path = ROOT):
    """Run `python -m redactor` and return the finished process."""
    return subprocess.run(
        [sys.executable, "-m", "redactor", *args],
        input=stdin,
        capture_output=True,
        cwd=cwd,
    )


def stderr_text(process) -> str:
    return process.stderr.decode("utf-8").replace("\r\n", "\n")


def expected_output(data: bytes) -> bytes:
    """What the stream produces in-process, with the provided rules."""
    stream = RedactionStream(Redactor(load_rules(ROOT / "rules.yaml")))
    return stream.feed(data) + stream.finish()


def json_line_of_length(length: int) -> bytes:
    """A valid JSON record that is exactly `length` bytes long.

    The filler is spaces on purpose: a megabyte of letters would send the
    provided e-mail pattern into quadratic backtracking (see test_stream.py).
    """
    return b'{"k":"' + b" " * (length - 8) + b'"}'


@pytest.fixture(scope="module")
def sample_run():
    """One run of the tool over the provided input file."""
    return run_cli("input.ndjson")


# --- output -------------------------------------------------------------------


def test_file_argument_writes_the_redacted_ndjson_to_stdout(sample_run):
    assert sample_run.stdout == expected_output(SAMPLE)


def test_stdin_gives_the_same_result_as_a_file_argument(sample_run):
    from_stdin = run_cli(stdin=SAMPLE)
    assert from_stdin.stdout == sample_run.stdout
    assert from_stdin.returncode == sample_run.returncode
    assert stderr_text(from_stdin) == stderr_text(sample_run)


def test_stdout_is_binary_safe_on_every_platform(sample_run):
    # Text-mode stdout on Windows would write "\r\n" for every line.
    assert b"\r" not in sample_run.stdout
    assert sample_run.stdout.count(b"\n") == 50


def test_stdout_holds_nothing_but_ndjson(sample_run):
    for line in sample_run.stdout.split(b"\n"):
        if line:
            json.loads(line)


def test_a_last_line_without_a_newline_on_stdin():
    process = run_cli(stdin=b'{"a":1}\n{"body":{"password":"x"}}')
    assert process.stdout == b'{"a":1}\n{"body":{"password":"****"}}\n'
    assert process.returncode == EXIT_OK


def test_empty_input():
    process = run_cli(stdin=b"")
    assert process.stdout == b""
    assert process.returncode == EXIT_OK
    assert "0 lines" in stderr_text(process)


def test_the_tool_is_idempotent_end_to_end(sample_run):
    second = run_cli(stdin=sample_run.stdout)
    assert second.stdout == sample_run.stdout
    # The placeholders are valid records now, so nothing is replaced this time
    # and nothing is left to redact.
    assert second.returncode == EXIT_OK
    lines = stderr_text(second).splitlines()
    assert lines[0] == "redactor: 50 lines: 48 processed, 2 blank, 0 replaced"
    assert all(line.endswith(" 0") for line in lines[2:])


# One transaction in the shape of the brief, with every kind of sensitive
# value the rules target: credentials in headers, nested fields, a card and a
# token inside free text, a form-encoded field, a query string, and JSON
# stored in a string. The expected output is written out by hand.
GOLDEN_RECORD = {
    "ts": "2025-03-01T12:00:00Z",
    "method": "POST",
    "path": "/v1/pay?token=tok_123&page=2",
    "headers": {"Authorization": "Bearer secret-token", "X-Api-Key": "key-1", "Content-Type": "application/json"},
    "body": {
        "user": {"email": "ann@example.com", "password": "hunter2"},
        "card": {"card_number": "4111111111111111", "cvv": "123"},
        "note": "backup card 5555 5555 5555 4444, id_token eyJhbGciOiJIUzI1NiJ9.eyJhIjoiPz8_In0.sig-_x",
        "form": "email=bob%40example.com&password=pw&remember=on",
    },
    "response": {
        "status": 200,
        "headers": {"Set-Cookie": "session=abc"},
        "body": '{"token":"t-1","items":["carol@example.com"]}',
    },
}


def value_digest(text: str) -> str:
    return sha256_digest(text, tagged=False)


def test_one_record_with_every_kind_of_sensitive_value():
    line = json.dumps(GOLDEN_RECORD, separators=(",", ":")).encode("utf-8") + b"\n"
    process = run_cli(stdin=line)

    assert process.stdout.endswith(b"\n") and b"\n" not in process.stdout[:-1]  # one compact line
    assert json.loads(process.stdout) == {
        "ts": "2025-03-01T12:00:00Z",
        "method": "POST",
        "path": "/v1/pay?token=****&page=2",  # `token` is a key rule, also in a query string
        "headers": {
            "Authorization": "****",  # mask
            "X-Api-Key": sha256_digest("key-1", tagged=True),  # hash under a key rule: tagged
            "Content-Type": "application/json",
        },
        "body": {
            "user": {"email": value_digest("ann@example.com"), "password": "****"},
            "card": {"card_number": "************1111"},  # partial; `cvv` is removed
            "note": "backup card ***************4444, id_token ****",  # Luhn-valid card and a JWT in text
            "form": f"email={value_digest('bob@example.com')}&password=****&remember=on",
        },
        "response": {
            "status": 200,
            "headers": {"Set-Cookie": "****"},
            "body": '{"token":"****","items":["' + value_digest("carol@example.com") + '"]}',
        },
    }
    for secret in (b"secret-token", b"key-1", b"hunter2", b"ann@", b"bob%40", b"carol@", b"4111", b"5555", b"eyJ", b"t-1", b"session=abc", b"tok_123", b'"cvv"'):
        assert secret not in process.stdout
    assert stderr_text(process).splitlines() == [
        "redactor: 1 lines: 1 processed, 0 blank, 0 replaced",
        "redactor: redactions by rule:",
        "  auth-headers            2",  # Authorization, Set-Cookie
        "  api-key-names           1",
        "  secret-fields           4",  # the query string, two passwords, the embedded token
        "  card-number-fields      1",
        "  cvv-fields              1",
        "  email                   3",
        "  jwt                     1",
        "  credit-card             1",
        "  credit-card-19-grouped  0",
        "  api-key-prefix          0",
    ]
    assert process.returncode == EXIT_OK


# --- streaming through real pipes ---------------------------------------------


def read_line_within(pipe, process, timeout: float = 30) -> bytes:
    """Read one line from `pipe`; fail instead of hanging if none arrives in time."""
    lines: list[bytes] = []
    reader = threading.Thread(target=lambda: lines.append(pipe.readline()), daemon=True)
    reader.start()
    reader.join(timeout)
    if reader.is_alive():
        process.kill()
        pytest.fail(f"no output line within {timeout} seconds")
    return lines[0]


def test_each_record_is_answered_while_the_input_is_still_open():
    # A record goes in and its redacted line comes out before the next one is
    # sent and long before stdin is closed. A tool that read its whole input
    # first would produce nothing here until the end.
    with subprocess.Popen(
        [sys.executable, "-m", "redactor"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ROOT,
    ) as process:
        for number in (1, 2, 3):
            process.stdin.write(b'{"n":%d,"password":"p%d"}\n' % (number, number))
            process.stdin.flush()
            assert read_line_within(process.stdout, process) == b'{"n":%d,"password":"****"}\n' % number
        rest, errors = process.communicate(timeout=30)  # closes stdin
    assert rest == b""
    assert process.returncode == EXIT_OK
    assert errors.decode("utf-8").splitlines()[0] == "redactor: 3 lines: 3 processed, 0 blank, 0 replaced"


def test_records_that_span_the_read_chunks_are_redacted_whole():
    # The tool reads 64 KiB at a time. 3,000 records of varying length put a
    # chunk boundary inside records and inside values, and one record is
    # longer than a chunk by itself. Every output line is checked.
    def pad(number: int) -> bytes:
        return b" " * (100_000 if number == 1500 else number % 97)

    records = [
        b'{"n":%d,"password":"p%d","email":"user%d@example.com","pad":"%s"}' % (n, n, n, pad(n))
        for n in range(1, 3001)
    ]
    data = b"\n".join(records) + b"\n"
    assert len(data) > 5 * 65536

    process = run_cli(stdin=data)
    lines = process.stdout.split(b"\n")
    assert lines.pop() == b""
    assert len(lines) == 3000
    for number, line in enumerate(lines, start=1):
        digest = value_digest(f"user{number}@example.com").encode("ascii")
        assert line == b'{"n":%d,"password":"****","email":"%s","pad":"%s"}' % (number, digest, pad(number))
    assert process.returncode == EXIT_OK
    text = stderr_text(process)
    assert text.splitlines()[0] == "redactor: 3000 lines: 3000 processed, 0 blank, 0 replaced"
    assert f"  {'secret-fields':<22}  3000" in text
    assert f"  {'email':<22}  3000" in text


# --- stderr -------------------------------------------------------------------


def test_stderr_holds_only_the_summary(sample_run):
    # Lines 20, 21 and 50 were replaced. They are counted, not reported one
    # by one: the placeholders on stdout say which lines and why.
    assert stderr_text(sample_run).splitlines() == [
        "redactor: 50 lines: 45 processed, 2 blank, 3 replaced (invalid_json: 3)",
        "redactor: redactions by rule:",
        "  auth-headers            9",
        "  api-key-names           8",
        "  secret-fields           10",
        "  card-number-fields      5",
        "  cvv-fields              1",
        "  email                   31",
        "  jwt                     4",
        "  credit-card             17",
        "  credit-card-19-grouped  0",
        "  api-key-prefix          2",
    ]


def test_stderr_never_contains_input_data(sample_run):
    text = stderr_text(sample_run)
    for fragment in INPUT_FRAGMENTS:
        assert fragment not in text


def test_refused_lines_leave_no_trace_on_stdout(sample_run):
    # Line 20 is cut off inside a JWT, line 21 is a log line with an e-mail
    # address, line 50 is cut off inside an e-mail address.
    fragments = (
        b'"/v1/pay"', b"10:00:19Z",  # line 20
        b"erin@example.com", b"upstream timeout",  # line 21
        b"trunc@exam", b'"/v1/x"', b"10:00:50Z",  # line 50
    )
    for fragment in fragments:
        assert fragment in SAMPLE
        assert fragment not in sample_run.stdout


@pytest.mark.parametrize(
    "data",
    [SAMPLE, b'{"body":{"password":"x"}}'],
    ids=["the sample", "a last line without a newline"],
)
def test_the_summary_is_written_after_the_last_record(data):
    # With both streams sent into one pipe, the bytes arrive in the order in
    # which they were written.
    merged = subprocess.run(
        [sys.executable, "-m", "redactor"],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=ROOT,
    ).stdout
    records = expected_output(data)
    assert merged.startswith(records)
    assert merged[len(records) :].startswith(b"redactor: ")


def test_many_replaced_lines_add_nothing_to_stderr():
    # 25 broken lines, each holding a secret, with a good record after every
    # fifth one: 30 lines in all.
    lines_in = []
    for number in range(1, 26):
        lines_in.append(b'{"password":"hunter2-%d", "user":"erin@example.com"' % number)  # no "}"
        if number % 5 == 0:
            lines_in.append(b'{"body":{"password":"x"}}')
    process = run_cli(stdin=b"\n".join(lines_in) + b"\n")

    # Every placeholder sits on the line of the record it replaced.
    lines_out = process.stdout.split(b"\n")[:-1]
    assert len(lines_out) == len(lines_in) == 30
    for number, (line_in, line_out) in enumerate(zip(lines_in, lines_out), start=1):
        if b"hunter2" in line_in:
            assert line_out == b'{"redactor_error":"invalid_json","line":%d}' % number
        else:
            assert line_out == b'{"body":{"password":"****"}}'

    # stderr: the totals, the header and one line per rule. Nothing per record.
    text = stderr_text(process)
    lines = text.splitlines()
    assert lines[0] == "redactor: 30 lines: 5 processed, 0 blank, 25 replaced (invalid_json: 25)"
    assert lines[1] == "redactor: redactions by rule:"
    assert len(lines) == 2 + 10
    assert "hunter2" not in text and "erin" not in text and "line " not in text
    assert process.returncode == EXIT_RECORDS_REPLACED


def test_the_summary_counts_replaced_lines_per_reason():
    too_long = json_line_of_length(DEFAULT_MAX_LINE_BYTES + 1)  # one byte over the limit
    data = (
        b"not json\n"
        b'{"name":"caf\xe9"}\n'  # 0xE9 alone is Latin-1, not UTF-8
        + too_long
        + b"\n"
        b"also not json\n"
        b'{"a":1}\n'
    )
    process = run_cli(stdin=data)
    assert stderr_text(process).splitlines()[0] == (
        "redactor: 5 lines: 1 processed, 0 blank, 4 replaced "
        "(invalid_json: 2, invalid_utf8: 1, line_too_long: 1)"
    )
    assert process.returncode == EXIT_RECORDS_REPLACED


# --- exit codes ---------------------------------------------------------------


def test_exit_code_0_when_every_record_was_processed():
    process = run_cli(stdin=b'{"body":{"password":"x"}}\n\n{"a":1}\n')
    assert process.returncode == EXIT_OK == 0
    assert "redactor: 3 lines: 2 processed, 1 blank, 0 replaced" in stderr_text(process)


def test_exit_code_3_when_a_record_was_replaced(sample_run):
    assert sample_run.returncode == EXIT_RECORDS_REPLACED == 3


def test_exit_code_1_when_the_input_file_cannot_be_read():
    process = run_cli("no-such-file.ndjson")
    assert process.returncode == EXIT_IO_ERROR == 1
    assert process.stdout == b""
    assert "input/output error" in stderr_text(process)


def test_a_reader_that_goes_away_ends_the_run_with_exit_code_1(tmp_path):
    # `redactor big.ndjson | head -1`: the reader closes the pipe while the
    # tool still has most of its output to write.
    record = b'{"user":"dana@example.com","body":{"password":"hunter2"}}\n'
    big = tmp_path / "big.ndjson"
    big.write_bytes(record * 20_000)  # over 1 MB, far more than a pipe holds

    with subprocess.Popen(
        [sys.executable, "-m", "redactor", str(big)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ROOT,
    ) as process:
        first_line = process.stdout.readline()
        process.stdout.close()  # the reader goes away
        errors = process.stderr.read().decode("utf-8")

    assert first_line == expected_output(record)
    assert process.returncode == EXIT_IO_ERROR
    # One plain message. Without care Python reports the failed flush a
    # second time at exit and changes the exit code to 120.
    lines = errors.splitlines()
    assert len(lines) == 1 and lines[0].startswith("redactor: input/output error:")
    assert "Traceback" not in errors
    for fragment in INPUT_FRAGMENTS:
        assert fragment not in errors


@pytest.mark.parametrize(
    "arguments",
    [
        ["--no-such-option"],
        ["one.ndjson", "two.ndjson"],
    ],
)
def test_exit_code_2_for_invalid_arguments(arguments):
    process = run_cli(*arguments, stdin=SAMPLE)
    assert process.returncode == EXIT_USAGE == 2
    assert process.stdout == b""


# --- rules: fail closed -------------------------------------------------------


def test_missing_rules_file_stops_before_any_output():
    process = run_cli("--rules", "no-such-rules.yaml", "input.ndjson")
    assert process.returncode == EXIT_USAGE
    assert process.stdout == b""
    assert "cannot load rules" in stderr_text(process)


def test_invalid_rules_file_stops_before_any_output(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "version: 1\nvalue_rules:\n  - name: email\n    pattern: '@'\n    actoin: hash\n",
        encoding="utf-8",
    )
    process = run_cli("--rules", str(rules), stdin=SAMPLE)
    assert process.returncode == EXIT_USAGE
    # Not one byte of the input may be passed on when the rules are unusable.
    assert process.stdout == b""
    assert "actoin" in stderr_text(process)


def test_default_rules_file_is_rules_yaml_in_the_current_directory(tmp_path):
    # tmp_path has no rules.yaml, so the default cannot be loaded there.
    process = run_cli(stdin=SAMPLE, cwd=tmp_path)
    assert process.returncode == EXIT_USAGE
    assert process.stdout == b""


def test_a_different_rules_file_changes_what_is_redacted():
    record = b'{"headers":{"Authorization":"Bearer t"},"body":{"pin":"4321","password":"p"}}\n'
    process = run_cli("--rules", str(ALTERNATIVE_RULES), stdin=record)
    assert json.loads(process.stdout) == {
        "headers": {"Authorization": "Bearer t"},
        "body": {"pin": "[REDACTED]", "password": "p"},
    }
    assert "pin-code" in stderr_text(process)
    assert "auth-headers" not in stderr_text(process)


# --- the line limit -----------------------------------------------------------


def test_a_line_over_one_mebibyte_is_replaced_and_the_limit_itself_is_allowed():
    at_limit = json_line_of_length(DEFAULT_MAX_LINE_BYTES)
    over_limit = b'{"password":"hunter2","k":"' + b" " * DEFAULT_MAX_LINE_BYTES + b'"}'
    process = run_cli(stdin=at_limit + b"\n" + over_limit + b"\n" + b'{"password":"x"}\n')
    assert process.stdout.split(b"\n") == [
        at_limit,
        b'{"redactor_error":"line_too_long","line":2}',
        b'{"password":"****"}',
        b"",
    ]
    # Nothing of the discarded line is passed on.
    assert b"hunter2" not in process.stdout
    assert process.returncode == EXIT_RECORDS_REPLACED
    assert "3 lines: 2 processed, 0 blank, 1 replaced (line_too_long: 1)" in stderr_text(process)


@pytest.mark.parametrize(
    "arguments",
    [
        ["--max-line-bytes", "300"],
        ["--max-line-bytes=300", "input.ndjson"],
    ],
)
def test_the_line_limit_is_not_a_command_line_option(arguments):
    process = run_cli(*arguments, stdin=SAMPLE)
    assert process.returncode == EXIT_USAGE
    assert process.stdout == b""
    assert "unrecognized arguments: --max-line-bytes" in stderr_text(process)


# --- the installed command ----------------------------------------------------


def test_the_installed_redactor_command_behaves_like_python_m(sample_run):
    name = "redactor.exe" if os.name == "nt" else "redactor"
    command = Path(sys.executable).with_name(name)
    if not command.exists():
        pytest.skip("the project is not installed in this environment")
    process = subprocess.run([str(command), "input.ndjson"], capture_output=True, cwd=ROOT)
    assert process.stdout == sample_run.stdout
    assert process.returncode == sample_run.returncode

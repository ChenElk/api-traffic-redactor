"""End-to-end tests of the command-line tool, run as a real process.

Each test starts `python -m redactor` with real pipes, so what is checked is
what a shell would see: the exact bytes on stdout, the text on stderr and the
exit code.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from redactor.cli import EXIT_IO_ERROR, EXIT_OK, EXIT_RECORDS_REPLACED, EXIT_USAGE
from redactor.engine import Redactor
from redactor.rules import load_rules
from redactor.stream import RedactionStream

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
    # The placeholders are valid records now, so nothing is replaced this time.
    assert second.returncode == EXIT_OK
    assert "replaced" not in stderr_text(second)


# --- stderr -------------------------------------------------------------------


def test_summary_and_reports_go_to_stderr(sample_run):
    assert stderr_text(sample_run).splitlines() == [
        "redactor: line 20: invalid_json, replaced by a placeholder",
        "redactor: line 21: invalid_json, replaced by a placeholder",
        "redactor: line 50: invalid_json, replaced by a placeholder",
        "redactor: 50 lines: 45 processed, 2 blank, 3 replaced (invalid_json: 3)",
        "redactor: redactions by rule:",
        "  auth-headers        9",
        "  api-key-names       8",
        "  secret-fields       10",
        "  card-number-fields  5",
        "  cvv-fields          1",
        "  email               31",
        "  jwt                 2",
        "  credit-card         13",
        "  api-key-prefix      2",
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


def test_at_most_twenty_replaced_lines_are_reported_one_by_one():
    process = run_cli(stdin=b"not json\n" * 25 + b'{"a":1}\n')
    lines = stderr_text(process).splitlines()
    assert sum("replaced by a placeholder" in line for line in lines) == 20
    assert sum("more than 20 lines replaced" in line for line in lines) == 1
    assert "redactor: 26 lines: 1 processed, 0 blank, 25 replaced (invalid_json: 25)" in lines
    assert process.returncode == EXIT_RECORDS_REPLACED


# --- exit codes ---------------------------------------------------------------


def test_exit_code_0_when_every_record_was_processed():
    process = run_cli(stdin=b'{"body":{"password":"x"}}\n\n{"a":1}\n')
    assert process.returncode == EXIT_OK == 0
    assert "replaced" not in stderr_text(process)


def test_exit_code_3_when_a_record_was_replaced(sample_run):
    assert sample_run.returncode == EXIT_RECORDS_REPLACED == 3


def test_exit_code_1_when_the_input_file_cannot_be_read():
    process = run_cli("no-such-file.ndjson")
    assert process.returncode == EXIT_IO_ERROR == 1
    assert process.stdout == b""
    assert "input/output error" in stderr_text(process)


@pytest.mark.parametrize(
    "arguments",
    [
        ["--no-such-option"],
        ["--max-line-bytes", "0"],
        ["--max-line-bytes", "many"],
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


# --- options ------------------------------------------------------------------


def test_max_line_bytes_replaces_longer_lines():
    process = run_cli("--max-line-bytes", "300", "input.ndjson")
    lines = process.stdout.split(b"\n")
    # Line 1 of the sample is 551 bytes long, line 4 is 206.
    assert lines[0] == b'{"redactor_error":"line_too_long","line":1}'
    assert lines[3] == SAMPLE.split(b"\n")[3]
    assert process.returncode == EXIT_RECORDS_REPLACED
    assert "line_too_long" in stderr_text(process)


# --- the installed command ----------------------------------------------------


def test_the_installed_redactor_command_behaves_like_python_m(sample_run):
    name = "redactor.exe" if os.name == "nt" else "redactor"
    command = Path(sys.executable).with_name(name)
    if not command.exists():
        pytest.skip("the project is not installed in this environment")
    process = subprocess.run([str(command), "input.ndjson"], capture_output=True, cwd=ROOT)
    assert process.stdout == sample_run.stdout
    assert process.returncode == sample_run.returncode

"""Smoke tests of the container image, run only on request.

The image has to be built first, and Docker has to be available, so these
tests are skipped unless the image to test is named in the environment:

    docker build -t api-traffic-redactor:dev .
    REDACTOR_DOCKER_IMAGE=api-traffic-redactor:dev pytest tests/test_docker.py

They check what the deployment relies on: the same tool, the same rules and
the same output inside the container as outside, the service answering on
port 8080 as an unprivileged user, and a clean stop.
"""

import http.client
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = (ROOT / "input.ndjson").read_bytes()
IMAGE = os.environ.get("REDACTOR_DOCKER_IMAGE")

pytestmark = pytest.mark.skipif(
    not IMAGE or shutil.which("docker") is None,
    reason="set REDACTOR_DOCKER_IMAGE to a built image, with Docker available",
)


def docker(*args: str, stdin: bytes | None = None, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], input=stdin, capture_output=True, timeout=timeout)


def local_cli(data: bytes) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "redactor", "--rules", "rules.yaml"], input=data, capture_output=True, cwd=ROOT)


def request(port: int, method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        connection.request(method, path, body=body)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_the_command_line_tool_inside_the_image_gives_the_same_output():
    local = local_cli(SAMPLE)
    inside = docker("run", "--rm", "-i", IMAGE, "--rules", "/etc/redactor/rules.yaml", stdin=SAMPLE)
    assert inside.returncode == local.returncode == 3
    assert inside.stdout == local.stdout
    assert inside.stderr.decode("utf-8").replace("\r\n", "\n") == local.stderr.decode("utf-8").replace("\r\n", "\n")


def test_the_service_inside_the_image_answers_as_an_unprivileged_user_and_stops_cleanly():
    name = f"redactor-test-{os.getpid()}-{time.monotonic_ns()}"
    started = docker("run", "-d", "--name", name, "-p", "127.0.0.1:0:8080", IMAGE)
    assert started.returncode == 0, started.stderr.decode("utf-8", "replace")
    try:
        mapping = docker("port", name, "8080").stdout.decode("ascii").splitlines()[0]
        port = int(mapping.rsplit(":", 1)[1])

        deadline = time.monotonic() + 60
        while True:
            try:
                if request(port, "GET", "/healthz")[0] == 200:
                    break
            except OSError:
                pass
            assert time.monotonic() < deadline, docker("logs", name).stderr.decode("utf-8", "replace")
            time.sleep(0.1)

        status, body = request(port, "POST", "/redact", body=SAMPLE)
        assert status == 200
        assert body == local_cli(SAMPLE).stdout
        assert docker("exec", name, "id", "-u").stdout.strip() == b"10001"

        assert docker("stop", "-t", "20", name).returncode == 0
        assert docker("inspect", "-f", "{{.State.ExitCode}}", name).stdout.strip() == b"0"
        log = docker("logs", name)
        assert b"hunter2" not in log.stdout + log.stderr and b"@" not in log.stdout + log.stderr
    finally:
        docker("rm", "-f", name)

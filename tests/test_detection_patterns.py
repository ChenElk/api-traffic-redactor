"""Tests for the detection patterns in rules.yaml: what they find and what they leave alone.

The engine tests check how rules are applied. These tests check the rules
themselves, against the real rules.yaml:

  * JWTs. The brief reports that the provided pattern "misses some JWTs seen
    in production samples". The pattern used the standard base64 alphabet
    (`+`, `/`, `=`), while the three parts of a JWT are base64url (`-`, `_`,
    no padding; RFC 7515).
"""

import base64
import json
from pathlib import Path

import pytest

from redactor.engine import Redactor
from redactor.rules import load_rules
from redactor.stream import RedactionStream

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules(ROOT / "rules.yaml")
SAMPLE = (ROOT / "input.ndjson").read_bytes()
SAMPLE_LINES = SAMPLE.decode("utf-8").split("\n")


def redact_text(text: str) -> str:
    """Redact `text` as a string value under a key that no rule names."""
    return json.loads(Redactor(RULES).redact(json.dumps({"note": text})))["note"]


def redact_sample_line(number: int):
    """Redact line `number` (1-based) of input.ndjson and parse the result."""
    return json.loads(Redactor(RULES).redact(SAMPLE_LINES[number - 1]))


# --- JWT ----------------------------------------------------------------------


def b64url(data: bytes) -> str:
    """Encode the way a JWT does: URL-safe alphabet, padding removed."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(header: dict, payload: dict, signature: bytes) -> str:
    def encode(part: dict) -> str:
        return b64url(json.dumps(part, separators=(",", ":")).encode("utf-8"))

    return f"{encode(header)}.{encode(payload)}.{b64url(signature)}"


HS256 = {"alg": "HS256", "typ": "JWT"}
PLAIN_SIGNATURE = bytes(range(32))

# The two tokens of input.ndjson (synthetic). The first is matched by the
# provided pattern only up to the "_" in its signature; the second is not
# matched at all, because of the "_" in its payload.
SAMPLE_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
SAMPLE_TOKEN_SHORT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJhIjoiPz8_In0"
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

# (description, token, index of the part that holds the character, the character)
BASE64URL_CASES = [
    ("underscore in the payload", make_jwt(HS256, {"a": "???"}, PLAIN_SIGNATURE), 1, "_"),
    ("hyphen in the payload", make_jwt(HS256, {"a": "??>"}, PLAIN_SIGNATURE), 1, "-"),
    ("underscore in the header", make_jwt({"alg": "HS256", "kid": "???"}, {"sub": "1"}, PLAIN_SIGNATURE), 0, "_"),
    ("hyphen in the header", make_jwt({"alg": "HS256", "kid": ">>>"}, {"sub": "1"}, PLAIN_SIGNATURE), 0, "-"),
    ("underscore in the signature", make_jwt(HS256, {"sub": "1"}, b"\xff" * 32), 2, "_"),
    ("hyphen in the signature", make_jwt(HS256, {"sub": "1"}, b"\xfb\xef\xbe" * 11), 2, "-"),
    ("the first token of input.ndjson", SAMPLE_TOKEN, 2, "_"),
    ("the second token of input.ndjson", SAMPLE_TOKEN_SHORT, 1, "_"),
]


@pytest.mark.parametrize(
    ("token", "part", "character"),
    [case[1:] for case in BASE64URL_CASES],
    ids=[case[0] for case in BASE64URL_CASES],
)
def test_a_jwt_with_base64url_characters_is_masked_whole(token, part, character):
    parts = token.split(".")
    assert len(parts) == 3 and character in parts[part]  # the case tests what it says

    redacted = redact_text(f"session {token} expired")

    assert redacted == "session **** expired"
    # Nothing of the token is left: not one part, and no tail of a part.
    for piece in parts:
        assert piece[-8:] not in redacted


@pytest.mark.parametrize(
    ("template", "expected"),
    [
        ("{}", "****"),
        ("Bearer {}", "Bearer ****"),
        ("forwarded header was Bearer {}", "forwarded header was Bearer ****"),
        ("cookie jwt={}; Path=/", "cookie jwt=****; Path=/"),
        ("/callback?id_token={}&state=7", "/callback?id_token=****&state=7"),
        ('{{"access_token":"{}","expires_in":3600}}', '{"access_token":"****","expires_in":3600}'),
    ],
)
def test_a_jwt_is_masked_wherever_it_appears(template, expected):
    assert redact_text(template.format(SAMPLE_TOKEN_SHORT)) == expected


def test_a_jwt_without_a_signature_is_masked():
    # An unsecured JWT ("alg":"none") ends with a dot and an empty third part.
    token = make_jwt({"alg": "none"}, {"sub": "???"}, b"")
    assert token.endswith(".") and "_" in token
    assert redact_text(f"got {token} from client") == "got **** from client"


def test_sample_line_11_token_inside_json_inside_a_string():
    body = json.loads(redact_sample_line(11)["response"]["body"])
    assert body["access_token"] == "****"


def test_sample_line_15_no_tail_of_the_signature_is_left():
    # The provided pattern stopped at the "_" and left "****_adQssw5c".
    body = redact_sample_line(15)["body"]
    assert body == {"id_token": "****", "note": "forwarded header was Bearer ****"}


def test_sample_line_16_token_inside_a_sentence():
    assert redact_sample_line(16)["body"]["msg"] == "session **** expired, retry"


def test_no_token_material_is_left_in_the_output_of_the_sample():
    stream = RedactionStream(Redactor(RULES))
    output = (stream.feed(SAMPLE) + stream.finish()).decode("utf-8")
    # Every "eyJ" in input.ndjson belongs to a token (line 20, a truncated
    # token in a truncated record, is replaced by a placeholder).
    assert b"eyJ" in SAMPLE
    assert "eyJ" not in output
    for token in (SAMPLE_TOKEN, SAMPLE_TOKEN_SHORT):
        for piece in token.split("."):
            assert piece[-8:] not in output


@pytest.mark.parametrize(
    "text",
    [
        "eyJ is how every JWT starts",
        "the eyJustInTime compiler",
        "see docs.example.com/eyJ.html",
        "version 1.2.3 of eye.joe.example",
    ],
)
def test_text_that_only_resembles_a_jwt_is_left_alone(text):
    assert redact_text(text) == text

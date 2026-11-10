"""Integration test: the engine driven by a completely different rules file.

Nothing in engine.py or actions.py may depend on the rules.yaml of the
assignment. tests/data/alt_rules.yaml uses other rule names, field names,
patterns and settings, and the same code must follow it without changes.
"""

import json
from pathlib import Path

import pytest

from redactor.actions import ActionSettings, sha256_digest
from redactor.engine import Redactor
from redactor.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent
ALTERNATIVE = load_rules(ROOT / "tests" / "data" / "alt_rules.yaml")
PROVIDED = load_rules(ROOT / "rules.yaml")

RECORD = {
    "ts": "2025-02-01T08:00:00Z",
    "method": "POST",
    "path": "/v2/visits?pin=4321&room=7",
    "headers": {
        "X-Device-Token": "dev-abc",
        "Authorization": "Bearer abc.def.ghi",
        "X-Forwarded-For": "10.1.2.3",
    },
    "body": {
        "patient": {
            "ssn": "123-45-6789",
            "name": "Ivy Chen",
            "phone": "+1 (415) 555-0132",
            "email": "ivy@example.com",
        },
        "diagnosis": "confidential",
        "pin_code": 9876,
        "password": "hunter2",
        "notes": ["plate ABC-1234 seen from 192.168.0.17", "see TICKET-42"],
        "audit": '{"national_id":"987654321","diagnosis":"x"}',
    },
    "response": {"status": 201, "headers": {"X-Session-Id": "sess-1"}, "body": None},
}
LINE = json.dumps(RECORD)


def key_digest(value):
    return sha256_digest(value, tagged=True)


def value_digest(value):
    return sha256_digest(value, tagged=False)


def test_the_alternative_file_shares_nothing_with_the_provided_one():
    assert set(ALTERNATIVE.rule_names).isdisjoint(PROVIDED.rule_names)
    assert ALTERNATIVE.settings == ActionSettings(
        mask_replacement="[REDACTED]", keep_last=2, fill="#"
    )
    assert ALTERNATIVE.settings != PROVIDED.settings


def test_a_record_is_redacted_according_to_the_alternative_file():
    redactor = Redactor(ALTERNATIVE)
    out = json.loads(redactor.redact(LINE))

    assert out == {
        "ts": "2025-02-01T08:00:00Z",
        "method": "POST",
        # `pin` is a query parameter, masked with this file's replacement text
        # (percent-encoded, as it sits in a query string).
        "path": "/v2/visits?pin=%5BREDACTED%5D&room=7",
        "headers": {
            "X-Device-Token": key_digest("dev-abc"),
            "Authorization": "Bearer abc.def.ghi",
            "X-Forwarded-For": value_digest("10.1.2.3"),
        },
        "body": {
            "patient": {
                "ssn": "#########89",
                "name": "Ivy Chen",
                "phone": "[REDACTED]",
                "email": "ivy@example.com",
            },
            # "diagnosis" is removed.
            "pin_code": "[REDACTED]",
            "password": "hunter2",
            "notes": [f"plate ######34 seen from {value_digest('192.168.0.17')}", "see "],
            "audit": '{"national_id":"#######21"}',
        },
        "response": {
            "status": 201,
            "headers": {"X-Session-Id": key_digest("sess-1")},
            "body": None,
        },
    }
    assert dict(redactor.counts) == {
        "device-headers": 2,
        "national-id": 2,
        "diagnosis": 2,
        "pin-code": 2,
        "ipv4-address": 2,
        "us-phone": 1,
        "license-plate": 1,
        "ticket-reference": 1,
    }


def test_what_only_the_provided_file_targets_is_left_alone():
    # No rule in the alternative file mentions these, so the engine must not
    # know about them either.
    out = json.loads(Redactor(ALTERNATIVE).redact(LINE))
    assert out["headers"]["Authorization"] == "Bearer abc.def.ghi"
    assert out["body"]["password"] == "hunter2"
    assert out["body"]["patient"]["email"] == "ivy@example.com"


def test_the_same_record_under_the_provided_file_is_redacted_differently():
    out = json.loads(Redactor(PROVIDED).redact(LINE))
    assert out["headers"]["Authorization"] == "****"
    assert out["body"]["password"] == "****"
    assert out["body"]["patient"]["email"] == value_digest("ivy@example.com")
    # And what only the alternative file targets is untouched here.
    assert out["body"]["patient"]["ssn"] == "123-45-6789"
    assert out["body"]["diagnosis"] == "confidential"
    assert out["body"]["pin_code"] == 9876
    assert out["headers"]["X-Device-Token"] == "dev-abc"


def test_the_alternative_file_is_idempotent_too():
    first = Redactor(ALTERNATIVE).redact(LINE)
    second_pass = Redactor(ALTERNATIVE)
    assert second_pass.redact(first) is first
    assert sum(second_pass.counts.values()) == 0


def test_bare_digests_do_not_match_any_value_rule_of_the_alternative_file():
    # The `ipv4-address` rule hashes with a bare digest. Idempotency holds only
    # if no value pattern of this file matches such a digest.
    for number in range(2_000):
        bare = value_digest(f"10.0.{number // 256}.{number % 256}")
        for text in (bare, f"from {bare}, {bare};{bare}.", f"id-{bare}-end", f"({bare})"):
            for rule in ALTERNATIVE.value_rules:
                assert rule.pattern.search(text) is None, f"{rule.name} matches a digest"


@pytest.mark.parametrize("rules", [PROVIDED, ALTERNATIVE], ids=["provided", "alternative"])
def test_counts_are_keyed_by_the_rule_names_of_the_loaded_file(rules):
    assert tuple(Redactor(rules).counts) == rules.rule_names

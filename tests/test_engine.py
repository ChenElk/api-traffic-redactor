"""Unit tests for the redaction engine (one JSON record in, one out).

Most tests use the project's rules.yaml. They check how rules are applied, not
what the patterns detect: the JWT and card-number patterns have their own
tests in test_detection_patterns.py.
"""

import itertools
import json
import re
import traceback
from pathlib import Path
from textwrap import dedent
from urllib.parse import unquote_plus

import pytest

from redactor.actions import STRICTEST_FIRST, ActionSettings, apply_action, sha256_digest
from redactor.engine import (
    MAX_STRING_NESTING,
    REASON_INVALID_EMBEDDED_JSON,
    REASON_INVALID_JSON,
    REASON_TOO_DEEP,
    RecordError,
    Redactor,
)
from redactor.rules import load_rules, parse_rules

ROOT = Path(__file__).resolve().parent.parent
PROVIDED = load_rules(ROOT / "rules.yaml")
SAMPLE_LINES = (ROOT / "input.ndjson").read_bytes().split(b"\n")
BARE_DIGEST = re.compile(r"[0-9a-f]{64}")


def sample_line(number: int) -> str:
    """Line `number` (1-based) of the provided input.ndjson."""
    return SAMPLE_LINES[number - 1].decode("utf-8")


def redact(line: str, rules=PROVIDED) -> str:
    return Redactor(rules).redact(line)


def redact_to_data(line: str, rules=PROVIDED):
    """Redact and parse the result, for assertions on individual fields."""
    return json.loads(redact(line, rules))


def rules_from(body: str):
    return parse_rules("version: 1\n" + dedent(body))


def value_rules(*specs):
    """Build a rule set from (name, pattern, action) triples, in the given order."""
    lines = ["version: 1", "value_rules:"]
    for name, pattern, action in specs:
        lines += [f"  - name: {name}", f"    pattern: '{pattern}'", f"    action: {action}"]
    return parse_rules("\n".join(lines) + "\n")


def key_digest(value: str) -> str:
    """What `hash` writes under a key rule: the tagged digest."""
    return sha256_digest(value, tagged=True)


def value_digest(value: str) -> str:
    """What `hash` writes for a value-rule match: the bare digest."""
    return sha256_digest(value, tagged=False)


def nest_in_strings(document, levels: int):
    """Wrap `document` in `levels` layers of JSON-encoded-as-a-string."""
    for _ in range(levels):
        document = {"payload": json.dumps(document)}
    return document


# --- key rules: scopes --------------------------------------------------------


def test_credentials_in_request_headers_are_masked_whatever_their_case():
    out = redact_to_data(
        '{"headers":{"authorization":"Bearer abc","AUTHORIZATION":"Basic dXNlcjpwYXNz",'
        '"Cookie":"session=abc123; theme=dark","Accept":"*/*"}}'
    )
    assert out["headers"] == {
        "authorization": "****",
        "AUTHORIZATION": "****",
        "Cookie": "****",
        "Accept": "*/*",
    }


def test_response_headers_are_headers_too():
    out = redact_to_data(
        '{"response":{"status":200,"headers":{"Set-Cookie":"session=abc123; HttpOnly"},"body":null}}'
    )
    assert out["response"] == {"status": 200, "headers": {"Set-Cookie": "****"}, "body": None}


def test_header_rule_does_not_reach_into_a_body():
    line = '{"body":{"Authorization":"Basic dXNlcjpwYXNz"}}'
    assert redact(line) == line


def test_body_rule_does_not_reach_into_headers():
    line = '{"headers":{"password":"a-header-with-an-odd-name"}}'
    assert redact(line) == line


def test_only_the_two_header_maps_of_a_record_are_header_scope():
    # An object that happens to be called "headers" inside a body is body scope.
    out = redact_to_data(
        '{"body":{"headers":{"Authorization":"Basic dXNlcjpwYXNz","password":"hunter2"}}}'
    )
    assert out["body"]["headers"] == {
        "Authorization": "Basic dXNlcjpwYXNz",
        "password": "****",
    }


def test_scope_any_rule_applies_in_headers_and_at_any_depth_of_a_body():
    out = redact_to_data(
        '{"headers":{"X-Api-Key":"k1"},"body":{"api_key":"k2","list":[{"ApiKey":"k3"}]}}'
    )
    assert out["headers"]["X-Api-Key"] == key_digest("k1")
    assert out["body"]["api_key"] == key_digest("k2")
    assert out["body"]["list"][0]["ApiKey"] == key_digest("k3")


def test_unknown_top_level_keys_are_treated_as_body():
    # Fail-safe: a field the record layout does not mention is still redacted.
    out = redact_to_data('{"password":"hunter2","extra":{"token":"t"}}')
    assert out == {"password": "****", "extra": {"token": "****"}}


def test_look_alike_key_names_are_left_alone():
    # input.ndjson line 48: password_hint, passwordless, tokenizer, secret_santa.
    line = sample_line(48)
    assert redact(line) is line


# --- key rules: actions and value types ---------------------------------------


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('{"cvv":"123","a":1,"b":2}', '{"a":1,"b":2}'),  # first member
        ('{"a":1,"cvv":"123","b":2}', '{"a":1,"b":2}'),  # middle
        ('{"a":1,"b":2,"cvv":"123"}', '{"a":1,"b":2}'),  # last
        ('{"cvv":"123"}', "{}"),  # only member
        ('{"cvv":"123","cvc":"456","a":1}', '{"a":1}'),  # two in a row
        ('{"a":1,"cvv":{"nested":[1,2]}}', '{"a":1}'),  # whatever the value is
    ],
)
def test_remove_drops_the_key_and_leaves_valid_json(body, expected):
    assert redact('{"body":' + body + "}") == '{"body":' + expected + "}"


def test_partial_under_a_key_rule():
    # input.ndjson line 38, including a value too short to keep four characters of.
    out = redact_to_data(sample_line(38))
    assert out["body"] == {
        "card_number": "****",
        "pan": "************1111",
        "card": {"card_number": "***************1111"},
    }


def test_a_number_under_a_key_rule_is_redacted_and_becomes_text():
    assert redact('{"body":{"card_number":4111111111111111,"count":3}}') == (
        '{"body":{"card_number":"************1111","count":3}}'
    )


def test_values_with_nothing_to_hide_are_kept_under_a_key_rule():
    # input.ndjson line 13: null, "", false and [] hold no secret. The number 0 does.
    out = redact_to_data(sample_line(13))
    assert out["body"] == {
        "password": None,
        "secret": "",
        "api_key": key_digest("0"),
        "token": False,
        "pwd": [],
        "email": None,
        "card_number": "",
    }


def test_key_rule_covers_every_value_inside_arrays_and_objects():
    out = redact_to_data(
        '{"headers":{"Authorization":["Bearer abc.def.ghi","Basic eA=="],'
        '"Set-Cookie":["session=abc123; HttpOnly","csrf=zzz"],'
        '"X-Forwarded-For":["10.0.0.1","10.0.0.2"]},'
        '"body":{"password":{"old":"a","new":["b",null,7]}}}'
    )
    assert out["headers"]["Authorization"] == ["****", "****"]
    assert out["headers"]["Set-Cookie"] == ["****", "****"]
    assert out["headers"]["X-Forwarded-For"] == ["10.0.0.1", "10.0.0.2"]
    assert out["body"]["password"] == {"old": "****", "new": ["****", None, "****"]}


def test_key_rule_takes_precedence_over_value_rules():
    # The value also matches the `api-key-prefix` value rule (action: mask).
    redactor = Redactor(PROVIDED)
    out = json.loads(redactor.redact('{"headers":{"X-Api-Key":"sk_live_abc123"}}'))
    assert out["headers"]["X-Api-Key"] == key_digest("sk_live_abc123")
    assert redactor.counts["api-key-names"] == 1
    assert redactor.counts["api-key-prefix"] == 0


# --- several key rules matching the same key ----------------------------------
# The strictest action wins (remove, mask, hash, partial), as for overlapping
# value rules. Which rule is chosen is tested in test_rules.py; these tests
# check what the engine then writes and counts.


def test_remove_wins_over_an_earlier_mask_rule_on_the_same_key():
    rules = rules_from(
        """
        key_rules:
          - name: mask-token
            scope: any
            match: { exact: [token] }
            action: mask
          - name: drop-token
            scope: any
            match: { regex: '(?i)^token$' }
            action: remove
        """
    )
    redactor = Redactor(rules)
    line = '{"headers":{"Token":"h"},"body":{"token":"hunter2","list":[{"token":"t"}],"a":1}}'
    assert redactor.redact(line) == '{"headers":{},"body":{"list":[{}],"a":1}}'
    # Counted under the rule that was applied, once per key.
    assert redactor.counts == {"mask-token": 0, "drop-token": 3}
    # The same choice is made for a form field and a query string.
    assert redact('{"body":"token=hunter2&x=1","path":"/cb?token=abc"}', rules) == (
        '{"body":"x=1","path":"/cb?"}'
    )


def test_hash_wins_over_an_earlier_partial_rule_on_the_same_key():
    rules = rules_from(
        """
        key_rules:
          - name: partial-pan
            scope: body
            match: { exact: [pan] }
            action: partial
          - name: hash-pan
            scope: body
            match: { exact: [pan] }
            action: hash
        """
    )
    redactor = Redactor(rules)
    first = redactor.redact('{"body":{"pan":"4111111111111111"}}')
    assert json.loads(first)["body"]["pan"] == key_digest("4111111111111111")
    assert redactor.counts == {"partial-pan": 0, "hash-pan": 1}
    assert redact(first, rules) is first


def test_two_equally_strict_key_rules_are_applied_and_counted_as_the_first_in_the_file():
    rules = rules_from(
        """
        settings:
          mask: { replacement: "[hidden]" }
        key_rules:
          - name: listed-first
            scope: any
            match: { exact: [token] }
            action: mask
          - name: listed-second
            scope: any
            match: { regex: '^token$' }
            action: mask
        """
    )
    redactor = Redactor(rules)
    assert redactor.redact('{"body":{"token":"hunter2"}}') == '{"body":{"token":"[hidden]"}}'
    assert redactor.counts == {"listed-first": 1, "listed-second": 0}


def test_the_chosen_key_rule_still_takes_precedence_over_value_rules():
    # Strictness decides between key rules only. A value rule does not take
    # part, even when its action (remove) is stricter than every key rule.
    rules = rules_from(
        r"""
        key_rules:
          - name: partial-contact
            scope: body
            match: { exact: [contact] }
            action: partial
          - name: hash-contact
            scope: body
            match: { exact: [contact] }
            action: hash
        value_rules:
          - name: drop-emails
            pattern: '[a-z]+@[a-z]+\.com'
            action: remove
        """
    )
    redactor = Redactor(rules)
    out = json.loads(redactor.redact('{"body":{"contact":"bob@example.com","note":"cc eve@example.com"}}'))
    assert out["body"] == {"contact": key_digest("bob@example.com"), "note": "cc "}
    assert redactor.counts == {"partial-contact": 0, "hash-contact": 1, "drop-emails": 1}


# --- hash: tagged under a key rule, bare for a value rule ---------------------


def test_hash_under_a_key_rule_is_tagged_and_stable_on_a_second_run():
    first = redact('{"headers":{"X-Api-Key":"k1"},"body":{"api_key":"k2"}}')
    out = json.loads(first)
    assert out["headers"]["X-Api-Key"].startswith("sha256:")
    assert out["body"]["api_key"] == key_digest("k2")
    # The key rule fires again on the same name and must recognise its output.
    assert redact(first) is first


def test_hash_from_a_value_rule_is_a_bare_digest_and_stable_on_a_second_run():
    first = redact('{"body":{"contact":"a@b.com","note":"cc c@d.org please"}}')
    out = json.loads(first)
    assert BARE_DIGEST.fullmatch(out["body"]["contact"])
    assert out["body"]["contact"] == value_digest("a@b.com")
    assert out["body"]["note"] == f"cc {value_digest('c@d.org')} please"
    # Stable because the digest no longer matches the e-mail pattern.
    assert redact(first) is first


def test_a_genuine_64_hex_key_is_hashed_not_mistaken_for_a_digest():
    genuine_key = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    output = redact('{"headers":{"X-Api-Key":"' + genuine_key + '"}}')
    assert genuine_key not in output
    assert json.loads(output)["headers"]["X-Api-Key"] == key_digest(genuine_key)


def test_key_rule_hash_on_a_form_field_is_tagged():
    out = redact_to_data('{"body":"api_key=abc&x=1"}')
    assert out["body"] == f"api_key={key_digest('abc')}&x=1"


def test_bare_digests_do_not_match_any_value_rule_of_the_provided_file():
    # A value-rule digest carries no marker, so idempotency rests on this:
    # no value pattern may match a digest, alone or surrounded by other text.
    for number in range(2_000):
        bare = value_digest(f"user{number}@example.com")
        for text in (bare, f"mail {bare}, {bare};{bare}.", f"id-{bare}-end", f"({bare})"):
            for rule in PROVIDED.value_rules:
                assert rule.pattern.search(text) is None, f"{rule.name} matches a digest"


# --- value rules --------------------------------------------------------------


def test_emails_are_found_at_any_depth_of_objects_and_arrays():
    out = redact_to_data(sample_line(3))
    orders = out["body"]["orders"]
    assert orders[0]["items"][0] == {
        "sku": "A1",
        "buyer": {"email": value_digest("alice@example.com")},
    }
    assert orders[0]["items"][1] == {
        "sku": "B2",
        "buyer": {"email": value_digest("bob@example.org")},
    }
    assert orders[1] == {"items": []}
    assert orders[2] == {"items": [[{"deep": [value_digest("carol@example.net")]}]]}


def test_emails_inside_text_and_strings_that_only_resemble_emails():
    out = redact_to_data(sample_line(29))
    assert out["body"]["emails"] == [
        value_digest("john.doe+tag@sub.example.co.uk"),
        value_digest("UPPER@EXAMPLE.COM"),
        "not-an-email@",
        "a@b",
        "x@y.z",
        "name@exa_mple.com",
    ]
    assert out["body"]["text"] == (
        f"mail {value_digest('bob@example.com')},{value_digest('carol@example.com')};"
        f"{value_digest('dave@example.com')}."
    )


def test_card_numbers_are_redacted_only_when_they_pass_luhn():
    # input.ndjson line 40: valid, invalid, valid. The invalid one must stay,
    # and must not stop the search for the one after it.
    out = redact_to_data(sample_line(40))
    assert out["body"]["text"] == (
        "first ************1111 then 4111111111111112 then ************4444."
    )


@pytest.mark.parametrize("line_number", [4, 35])
def test_a_sixteen_digit_number_that_fails_luhn_is_not_touched(line_number):
    line = sample_line(line_number)
    assert redact(line) is line


def test_secrets_inside_a_plain_text_body():
    out = redact_to_data(sample_line(9))
    assert out["body"] == (
        f"Hi team,\nplease reset the account for {value_digest('dave@example.com')}. "
        "Temporary key: ****. Thanks!"
    )


def test_text_around_a_redaction_is_preserved_including_non_ascii():
    output = redact(sample_line(7))
    note = json.loads(output)["body"]["note"]
    assert note == (
        f"名前: 田中 email {value_digest('tanaka@example.co.jp')} 😀 カード ************1881 です"
    )
    # Written as UTF-8 text, not as \uXXXX escapes.
    assert "Zürich" in output and "名前" in output and "\\u" not in output


def test_matches_next_to_emoji_are_found():
    out = redact_to_data(sample_line(46))
    assert out["body"]["note"] == (
        f"💳************1111💳 and 😀{value_digest('zed@example.com')}😀"
    )


def test_json_escapes_are_decoded_before_matching():
    # input.ndjson line 45 spells "@" as \u0040 and the leading "4" as \u0034.
    out = redact_to_data(sample_line(45))
    assert out["body"] == {
        "contact": value_digest("alice@example.com"),
        "card": "************1111",
    }


def test_an_escaped_newline_between_two_emails_separates_them():
    # input.ndjson line 39. Matching on the raw text would read "\na5@x.com"
    # as the address "na5@x.com" and leave a broken escape behind.
    out = redact_to_data(sample_line(39))
    addresses = [value_digest(f"a{n}@x.com") for n in range(1, 6)]
    assert out["body"]["cc"] == "{}, {}; {} {}\n{}".format(*addresses)


def test_value_rules_also_scan_header_values():
    out = redact_to_data('{"headers":{"X-Trace":"user a@b.com","Location":"/home"}}')
    assert out["headers"] == {
        "X-Trace": f"user {value_digest('a@b.com')}",
        "Location": "/home",
    }


def test_value_rules_do_not_scan_numbers():
    # A Luhn-valid number that is not a string, under a key no rule names.
    line = '{"body":{"n":4111111111111111,"ts_us":1705312800123456}}'
    assert redact(line) is line


def test_value_rules_do_not_rewrite_key_names():
    # Known limitation: a sensitive value used as a key name is not redacted.
    line = '{"body":{"a@b.com":{"plan":"free"}}}'
    assert redact(line) is line


def test_value_rule_with_remove_deletes_the_matched_text():
    rules = value_rules(("ticket", r"TICKET-\d+ ?", "remove"))
    assert redact('{"note":"see TICKET-123 for details"}', rules) == '{"note":"see for details"}'


def test_a_candidate_refused_by_the_validator_does_not_hide_the_next_one():
    # With separators allowed, "2024 4111 1111 1111" is found first and fails
    # Luhn. The real card starts inside that candidate.
    rules = rules_from(
        r"""
        value_rules:
          - name: card
            pattern: '\b\d(?:[ -]?\d){12,18}?\b'
            validator: luhn
            action: partial
        """
    )
    assert redact_to_data('"paid 2024 4111 1111 1111 1111 ok"', rules) == (
        "paid 2024 ***************1111 ok"
    )


def test_a_zero_width_pattern_changes_nothing_and_terminates():
    # `(?=a)` matches at a position without consuming anything.
    rules = value_rules(("lookahead", "(?=a)", "mask"))
    line = '"banana"'
    assert redact(line, rules) is line


# --- value rules: overlapping matches -----------------------------------------
# Policy: merge overlapping matches into one range, apply the strictest action
# among them once to the whole range, count the range once under that rule.


def run(text: str, rules):
    """Redact a top-level JSON string; return (result text, non-zero counts)."""
    redactor = Redactor(rules)
    result = json.loads(redactor.redact(json.dumps(text)))
    return result, {name: count for name, count in redactor.counts.items() if count}


def test_partial_overlap_is_merged_and_the_strictest_action_covers_all_of_it():
    rules = value_rules(("weak", "abcd", "partial"), ("strict", "cdef", "mask"))
    # "abcd" is [0,4) and "cdef" is [2,6): one range [0,6).
    assert run("abcdefgh", rules) == ("****gh", {"strict": 1})


def test_a_match_fully_inside_another_is_merged_into_it():
    rules = value_rules(("outer", "abcdef", "partial"), ("inner", "bcd", "hash"))
    # The whole outer range is hashed, not only the inner three characters.
    assert run("abcdef!", rules) == (value_digest("abcdef") + "!", {"inner": 1})


def test_a_chain_of_overlaps_becomes_one_range():
    rules = value_rules(
        ("first", "abc", "partial"), ("second", "cde", "hash"), ("third", "efg", "mask")
    )
    # "abc" and "efg" do not touch each other; "cde" links them.
    assert run("abcdefgh", rules) == ("****h", {"third": 1})


def test_matches_that_do_not_overlap_are_redacted_independently():
    rules = value_rules(("left", "abc", "mask"), ("right", "fgh", "hash"))
    assert run("abc--fgh", rules) == (
        "****--" + value_digest("fgh"),
        {"left": 1, "right": 1},
    )


def test_ranges_that_only_touch_are_not_merged():
    rules = value_rules(("left", "abc", "mask"), ("right", "def", "partial"))
    # [0,3) and [3,6) share no character.
    assert run("abcdef", rules) == ("****" + "***", {"left": 1, "right": 1})


@pytest.mark.parametrize(
    ("stricter", "weaker"), list(itertools.combinations(STRICTEST_FIRST, 2))
)
def test_the_stricter_action_wins_whatever_the_order_in_the_file(stricter, weaker):
    expected = apply_action(stricter, "abcdef", ActionSettings(), tagged_hash=False)
    for specs in (
        (("weak", "abcd", weaker), ("strict", "cdef", stricter)),
        (("strict", "cdef", stricter), ("weak", "abcd", weaker)),
    ):
        assert run("abcdef", value_rules(*specs)) == (expected, {"strict": 1})


def test_equal_strictness_is_decided_by_the_order_in_the_file():
    one_then_two = value_rules(("one", "abcd", "hash"), ("two", "cdef", "hash"))
    two_then_one = value_rules(("two", "cdef", "hash"), ("one", "abcd", "hash"))
    # Same action, so the text is the same; the count shows which rule was chosen.
    assert run("abcdef", one_then_two) == (value_digest("abcdef"), {"one": 1})
    assert run("abcdef", two_then_one) == (value_digest("abcdef"), {"two": 1})


def test_a_rule_without_a_validator_does_not_overlap_itself():
    # After a match the search resumes at its end: "aba" is found once in
    # "ababa", and "aa" twice in "aaaa" as two ranges that only touch.
    assert run("ababa", value_rules(("r", "aba", "mask"))) == ("****ba", {"r": 1})
    assert run("aaaa", value_rules(("r", "aa", "mask"))) == ("********", {"r": 2})


def test_a_rule_with_a_validator_finds_candidates_inside_an_accepted_match():
    # The validator judges one candidate at a time, so the search resumes one
    # character after an accepted match. Overlapping matches merge into one
    # range, counted once. Here every candidate of digits passes.
    rules = rules_from(
        r"""
        value_rules:
          - name: pairs
            pattern: '\d{2}'
            validator: luhn
            action: mask
        """
    )
    # Luhn-valid pairs that overlap: 26, 67, 75 (each passes), so "2675" is one range.
    assert run("x 2675 y", rules) == ("x **** y", {"pairs": 1})


def test_the_same_rule_twice_in_one_chain_is_still_one_range():
    rules = value_rules(("ends", "abc|efg", "partial"), ("middle", "cde", "mask"))
    assert run("abcdefg", rules) == ("****", {"middle": 1})


def test_overlap_in_the_provided_rules_leaves_no_part_of_either_match():
    # `api-key-prefix` (mask) matches "sk_live_abc" and `email` (hash) matches
    # the whole address. Mask is stricter and covers the merged range.
    assert redact_to_data('"key sk_live_abc@example.com now"') == "key **** now"


def test_card_number_inside_an_email_address_is_hashed_as_one_range():
    # `credit-card` (partial) and `email` (hash) both start at the first digit.
    address = "4111111111111111@example.com"
    assert redact_to_data(json.dumps(address)) == value_digest(address)


# --- JSON inside a string -----------------------------------------------------


def test_key_rules_reach_into_json_stored_in_a_string():
    # input.ndjson line 1: the response body is the *string* {"token":"abc123"}.
    out = redact_to_data(sample_line(1))
    assert out["response"]["body"] == '{"token":"****"}'


def test_key_and_value_rules_inside_a_stringified_request_body():
    # input.ndjson line 10.
    out = redact_to_data(sample_line(10))
    assert isinstance(out["body"], str)
    assert json.loads(out["body"]) == {
        "email": value_digest("carol@example.com"),
        "password": "****",
        "profile": {"card": "************4444"},
    }


def test_embedded_json_with_nothing_sensitive_keeps_its_exact_text():
    # The record is rewritten because of the cookie, but the embedded document
    # has nothing to redact and must keep its own spacing.
    out = redact_to_data('{"headers":{"Cookie":"x"},"body":"{ \\"a\\" : [ 1 , 2 ] }"}')
    assert out["body"] == '{ "a" : [ 1 , 2 ] }'


def test_a_json_array_in_a_string_is_decoded_too():
    out = redact_to_data('{"body":"[\\"a@b.com\\", {\\"password\\": \\"x\\"}]"}')
    assert json.loads(out["body"]) == [value_digest("a@b.com"), {"password": "****"}]


@pytest.mark.parametrize("scalar", ["true", "42", "null", "3.14"])
def test_a_string_holding_a_json_scalar_is_left_alone(scalar):
    line = '{"body":"' + scalar + '"}'
    assert redact(line) is line


# --- broken JSON inside a string: fail closed ---------------------------------


@pytest.mark.parametrize(
    "broken",
    [
        '{"password":"hunter2"',  # truncated
        '{"user":"bob","password":"hunter2"',
        '[{"note":"x"},{"token":"hunter2"',
        '{"api_key": "hunter2", }',  # trailing comma
        "{'password': 'hunter2'}",  # what Python prints for a dict
        '{"payload":"{\\"password\\":\\"hunter2\\"}"',  # the key is one level further in
    ],
)
def test_broken_embedded_json_that_shows_a_sensitive_key_refuses_the_record(broken):
    # Key rules cannot be applied without the structure, and no value rule
    # would recognise "hunter2". Letting the string through would leak it.
    with pytest.raises(RecordError) as error:
        redact(json.dumps({"body": broken}))
    assert error.value.reason == REASON_INVALID_EMBEDDED_JSON
    rendered = "".join(traceback.format_exception(error.value))
    assert "hunter2" not in rendered and "hunter2" not in repr(error.value)


def test_broken_json_in_a_form_field_refuses_the_record_too():
    with pytest.raises(RecordError) as error:
        redact('{"body":"payload=%7B%22password%22%3A%22hunter2&v=2"}')
    assert error.value.reason == REASON_INVALID_EMBEDDED_JSON


@pytest.mark.parametrize(
    "text",
    [
        "[INFO] user logged in",
        "[2025-01-15 10:00:20] WARN upstream timeout",
        "{name} joined the channel",
        "[1] see the footnote",
        '{"note":"cut off in the mid',  # broken JSON, but no key a rule targets
        "[1, 2, 3",
    ],
)
def test_plain_text_that_starts_with_a_bracket_is_not_refused(text):
    line = json.dumps({"body": text})
    assert redact(line) is line


def test_value_rules_still_scan_text_that_starts_with_a_bracket():
    assert redact_to_data('{"body":"[INFO] login by a@b.com"}')["body"] == (
        f"[INFO] login by {value_digest('a@b.com')}"
    )
    # Broken JSON without a sensitive key is text as well.
    assert redact_to_data(json.dumps({"body": '{"contact":"a@b.com'}))["body"] == (
        '{"contact":"' + value_digest("a@b.com")
    )


def test_counts_are_untouched_when_embedded_json_refuses_the_record():
    redactor = Redactor(PROVIDED)
    with pytest.raises(RecordError):
        # The cookie is handled before the broken body is reached.
        redactor.redact(json.dumps({"headers": {"Cookie": "c"}, "body": '{"password":"x"'}))
    assert sum(redactor.counts.values()) == 0


# --- the nesting limit for content inside strings: fail closed ----------------


def test_json_nested_in_strings_up_to_the_limit_is_fully_redacted():
    out = redact_to_data(json.dumps(nest_in_strings({"password": "hunter2"}, MAX_STRING_NESTING)))
    for _ in range(MAX_STRING_NESTING):
        out = json.loads(out["payload"])
    assert out == {"password": "****"}


def test_a_password_in_json_beyond_the_nesting_limit_refuses_the_record():
    # One layer too many: the innermost JSON would have to be left undecoded,
    # and its "password" key would never meet a key rule.
    line = json.dumps(nest_in_strings({"password": "hunter2"}, MAX_STRING_NESTING + 1))
    assert "hunter2" in line
    with pytest.raises(RecordError) as error:
        redact(line)
    assert error.value.reason == REASON_TOO_DEEP
    assert "hunter2" not in "".join(traceback.format_exception(error.value))


def test_any_json_at_the_nesting_limit_is_refused_because_its_keys_were_not_checked():
    line = json.dumps(nest_in_strings({"note": "harmless"}, MAX_STRING_NESTING + 1))
    with pytest.raises(RecordError) as error:
        redact(line)
    assert error.value.reason == REASON_TOO_DEEP


def test_plain_text_at_the_nesting_limit_is_scanned_not_refused():
    document = nest_in_strings({"note": "write to a@b.com", "tag": "[draft]"}, MAX_STRING_NESTING)
    output = redact(json.dumps(document))
    assert "a@b.com" not in output
    assert value_digest("a@b.com") in output


def test_a_sensitive_form_field_at_the_nesting_limit_refuses_the_record():
    line = json.dumps(nest_in_strings({"q": "a=1&password=hunter2"}, MAX_STRING_NESTING))
    with pytest.raises(RecordError) as error:
        redact(line)
    assert error.value.reason == REASON_TOO_DEEP


def test_json_in_a_form_field_at_the_nesting_limit_refuses_the_record():
    line = json.dumps(nest_in_strings({"q": "payload=%7B%22a%22%3A1%7D"}, MAX_STRING_NESTING))
    with pytest.raises(RecordError) as error:
        redact(line)
    assert error.value.reason == REASON_TOO_DEEP


def test_a_harmless_form_shaped_string_at_the_nesting_limit_is_not_refused():
    line = json.dumps(nest_in_strings({"q": "a=1&b=2", "pad": "QUJD=="}, MAX_STRING_NESTING))
    assert redact(line) is line


def test_an_ordinary_string_with_many_equals_signs_is_not_refused():
    # Each "=" makes the rest look like a form value once more, which walks
    # this string down to the nesting limit. It holds nothing a rule targets.
    line = '"Server=db;Database=x;User=sa;Encrypt=true;Timeout=30;Pool=5;App=web;Retry=3"'
    assert redact(line) is line


# --- form-encoded bodies and query strings ------------------------------------


def test_form_encoded_body():
    # input.ndjson line 8: an encoded e-mail, a password field, a card number.
    out = redact_to_data(sample_line(8))
    assert out["body"] == (
        f"email={value_digest('bob@example.com')}&password=****"
        "&card=************1111&remember=on"
    )


def test_query_string_in_the_request_path():
    # input.ndjson line 30.
    out = redact_to_data(sample_line(30))
    assert out["path"] == f"/v1/reset?token=****&email={value_digest('gina@example.com')}"


def test_untouched_form_fields_keep_their_original_encoding():
    out = redact_to_data('{"body":"q=a%20b%2Bc&password=x&lang=he"}')
    assert out["body"] == "q=a%20b%2Bc&password=****&lang=he"


@pytest.mark.parametrize(
    ("body", "expected"),
    [("cvv=123&x=1", "x=1"), ("x=1&cvv=123", "x=1"), ("x=1&cvv=123&y=2", "x=1&y=2")],
)
def test_remove_drops_a_form_field(body, expected):
    assert redact_to_data('{"body":"' + body + '"}')["body"] == expected


def test_a_question_mark_inside_a_value_does_not_hide_the_fields_before_it():
    out = redact_to_data('{"body":"password=x&q=what?&token=t"}')
    assert out["body"] == "password=****&q=what?&token=****"


def test_url_with_query_and_fragment():
    out = redact_to_data(
        '{"headers":{"Referer":"https://example.com/cb?token=abc&page=2#top"}}'
    )
    assert out["headers"]["Referer"] == "https://example.com/cb?token=****&page=2#top"


def test_the_fragment_of_a_url_is_not_part_of_the_last_value():
    # Without the split at "#", the fragment would be masked together with
    # the token and disappear from the output.
    out = redact_to_data('{"path":"/reset?token=abc#top"}')
    assert out["path"] == "/reset?token=****#top"


def test_spaces_in_a_form_value_are_decoded_before_matching():
    out = redact_to_data('{"body":"note=card+4111111111111111+ok&x=1"}')
    assert out["body"] == "note=card+************1111+ok&x=1"


def test_form_field_holding_json():
    out = redact_to_data('{"body":"payload=%7B%22password%22%3A%22x%22%7D&v=2"}')
    name, _, value = out["body"].partition("&")[0].partition("=")
    assert name == "payload"
    assert json.loads(unquote_plus(value)) == {"password": "****"}
    assert out["body"].endswith("&v=2")


def test_prose_containing_an_equals_sign_is_not_a_form():
    # input.ndjson line 41: "login attempt password=hunter2 for user=zed".
    # Known limitation: key=value inside a sentence is not decoded as a field.
    line = sample_line(41)
    assert redact(line) is line


def test_prose_is_never_re_encoded_as_a_form():
    # Treating this sentence as a field named "x" would write its value back
    # form-encoded, turning every space into "+".
    out = redact_to_data('"x=1 contact a@b.com now"')
    assert out == f"x=1 contact {value_digest('a@b.com')} now"


def test_base64_with_padding_is_not_damaged():
    # input.ndjson line 17: the response body is "UEsDBBQAAAAIAA==".
    line = sample_line(17)
    assert redact(line) is line


def test_a_form_shaped_string_is_still_scanned_as_a_whole():
    # Split at "=", neither half matches. The match spans the "=".
    rules = value_rules(("padded-token", r"tok_[A-Za-z0-9=]+\.[A-Za-z0-9=]+", "mask"))
    assert redact_to_data('"tok_abc==.def="', rules) == "****"


# --- what must not change -----------------------------------------------------


@pytest.mark.parametrize("line_number", [18, 23, 37, 43, 49])
def test_a_record_with_nothing_to_redact_is_returned_untouched(line_number):
    line = sample_line(line_number)
    assert redact(line) is line


def test_whitespace_between_tokens_survives_when_nothing_is_redacted():
    line = '{ "a" : 1 , "b" : [ 1 , 2 ] }'
    assert redact(line) is line


def test_numbers_keep_their_exact_spelling_in_a_rewritten_record():
    # input.ndjson line 28: 10.50, 1.0, 1e3 and a 20-digit integer.
    line = sample_line(28)
    expected = line.replace(
        '"card_number":4111111111111111', '"card_number":"************1111"'
    ).replace("tom@example.com", value_digest("tom@example.com"))
    output = redact(line)
    assert output == expected
    assert '"order_id":12345678901234567890,"amount":10.50,"ratio":1.0,"exp":1e3' in output
    # No HTML escaping of the characters around the address.
    assert "Tom & Jerry <" in output


def test_duplicate_keys_are_both_kept_and_both_redacted():
    # input.ndjson line 25: the key "email" appears twice in one object.
    line = sample_line(25)
    expected = line.replace(
        "first@example.com", value_digest("first@example.com")
    ).replace("second@example.com", value_digest("second@example.com"))
    assert redact(line) == expected


def test_a_top_level_array_is_redacted_like_any_other_value():
    # input.ndjson line 24.
    assert redact(sample_line(24)) == f'["{value_digest("a@b.com")}","************1111"]'


def test_a_top_level_string_is_redacted():
    assert redact('"contact a@b.com"') == f'"contact {value_digest("a@b.com")}"'


# --- lone surrogates: the output must always be writable as UTF-8 -------------
# The JSON escape \ud83d (half of an emoji) is legal JSON but decodes to a
# character that UTF-8 cannot encode.

LONE = "\\ud83d"  # as it is spelled inside a JSON text


@pytest.mark.parametrize(
    "line",
    [
        '{"odd":"' + LONE + '","password":"hunter2"}',  # in an untouched value
        '{"' + LONE + '":"v","password":"hunter2"}',  # in a key name
        '{"password":"hunter2' + LONE + '"}',  # in a value a key rule masks
        '{"api_key":"hunter2' + LONE + '"}',  # in a value a key rule hashes
        '{"card_number":"' + LONE + '4111111111111111"}',  # in a value a key rule partly masks
        '{"note":"' + LONE + ' hunter2@example.com"}',  # next to a value-rule match
        '{"body":"note=' + LONE + '+hunter2@example.com&x=1"}',  # in a rewritten form field
        # In JSON stored in a string, which is rewritten because of the password.
        json.dumps({"body": '{"n":"' + LONE + '","password":"hunter2"}'}),
    ],
)
def test_a_lone_surrogate_never_breaks_the_output_or_exposes_data(line):
    output = redact(line)
    # Strict UTF-8 encoding must succeed: this is what the writer will do.
    encoded = output.encode("utf-8")
    assert "hunter2" not in output
    # The result is still valid JSON, and stable on a second run.
    json.loads(encoded)
    assert redact(output) is output


def test_a_lone_surrogate_in_an_untouched_value_is_written_back_as_an_escape():
    output = redact('{"odd":"' + LONE + '","password":"x"}')
    assert output == '{"odd":"' + LONE + '","password":"****"}'
    assert json.loads(output) == {"odd": "\ud83d", "password": "****"}


# --- records that cannot be processed -----------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        sample_line(20),  # cut off in the middle of a JWT
        sample_line(21),  # a plain-text log line
        sample_line(50),  # cut off in the middle of an e-mail address
        "",
        "   ",
        "NaN",
        '{"a":Infinity}',
        '{"a":1} trailing',
        "{'a':1}",
        '{"a":"tab\there"}',  # a raw control character inside a string
    ],
)
def test_invalid_json_raises_a_record_error(line):
    with pytest.raises(RecordError) as error:
        redact(line)
    assert error.value.reason == REASON_INVALID_JSON


@pytest.mark.parametrize(
    "line",
    [
        "[" * 100_000 + "]" * 100_000,
        "[" * 5_000 + "]" * 5_000,
        '{"a":' * 5_000 + "1" + "}" * 5_000,
    ],
)
def test_nesting_too_deep_to_process_raises_a_record_error(line):
    with pytest.raises(RecordError) as error:
        redact(line)
    assert error.value.reason == REASON_TOO_DEEP


def test_a_record_error_never_carries_input_data():
    line = sample_line(50)
    assert "trunc@exam" in line
    with pytest.raises(RecordError) as error:
        redact(line)
    rendered = "".join(traceback.format_exception(error.value))
    for text in (str(error.value), repr(error.value), rendered):
        assert "trunc@exam" not in text
        assert "/v1/x" not in text
    # Nothing is chained for a logger to print: the JSONDecodeError that was
    # caught holds the whole line in its `doc` attribute.
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__ is True


def test_counts_are_untouched_by_a_record_that_fails():
    redactor = Redactor(PROVIDED)
    redactor.redact('{"body":{"password":"a"}}')
    before = dict(redactor.counts)

    with pytest.raises(RecordError):
        redactor.redact('{"body":{"password":"b"}')  # truncated
    # This one fails half-way through the walk, after `password` was handled.
    with pytest.raises(RecordError):
        redactor.redact('{"password":"c","deep":' + "[" * 5_000 + "]" * 5_000 + "}")

    assert dict(redactor.counts) == before


# --- counts and idempotency ---------------------------------------------------


def test_counts_start_at_zero_for_every_rule():
    assert dict(Redactor(PROVIDED).counts) == {name: 0 for name in PROVIDED.rule_names}


def test_counts_are_per_rule_and_accumulate_across_records():
    redactor = Redactor(PROVIDED)
    redactor.redact(
        '{"headers":{"Authorization":"Bearer x","X-Api-Key":"k"},'
        '"body":{"email":"a@b.com","cc":"c@d.com, e@f.com","cvv":"123","password":"p"}}'
    )
    redactor.redact('{"body":{"password":"q","note":"nothing here"}}')
    assert dict(redactor.counts) == {
        "auth-headers": 1,
        "api-key-names": 1,
        "secret-fields": 2,
        "card-number-fields": 0,
        "cvv-fields": 1,
        "email": 3,
        "jwt": 0,
        "credit-card": 0,
        "credit-card-19-grouped": 0,
        "api-key-prefix": 0,
    }


def test_a_value_that_is_already_redacted_is_not_counted():
    redactor = Redactor(PROVIDED)
    line = '{"body":{"password":"****","card_number":"************1111"}}'
    assert redactor.redact(line) is line
    assert sum(redactor.counts.values()) == 0


def _valid_sample_line_numbers():
    numbers = []
    for number, raw in enumerate(SAMPLE_LINES, start=1):
        try:
            json.loads(raw)
        except ValueError:
            continue
        numbers.append(number)
    return numbers


@pytest.mark.parametrize("line_number", _valid_sample_line_numbers())
def test_every_valid_sample_line_gives_valid_json_and_is_idempotent(line_number):
    first = redact(sample_line(line_number))
    json.loads(first)
    first.encode("utf-8")

    second_pass = Redactor(PROVIDED)
    assert second_pass.redact(first) is first
    assert sum(second_pass.counts.values()) == 0

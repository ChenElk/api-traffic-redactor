"""Unit tests for loading, validating and matching the redaction rules."""

from pathlib import Path
from textwrap import dedent

import pytest

from redactor.actions import ActionSettings, luhn_valid
from redactor.rules import (
    SCOPE_BODY,
    SCOPE_HEADERS,
    RulesError,
    load_rules,
    parse_rules,
)

PROVIDED_RULES = Path(__file__).resolve().parent.parent / "rules.yaml"


@pytest.fixture(scope="module")
def provided():
    """The rules.yaml shipped with the assignment."""
    return load_rules(PROVIDED_RULES)


def rules_from(body: str):
    """Parse a rules document given as an indented YAML snippet (version added)."""
    return parse_rules("version: 1\n" + dedent(body))


# --- the provided file ------------------------------------------------------


def test_provided_file_loads_with_all_rules_in_file_order(provided):
    assert provided.rule_names == (
        "auth-headers",
        "api-key-names",
        "secret-fields",
        "card-number-fields",
        "cvv-fields",
        "email",
        "jwt",
        "credit-card",
        "credit-card-19-grouped",
        "api-key-prefix",
    )
    assert provided.settings == ActionSettings(mask_replacement="****", keep_last=4, fill="*")


def test_provided_actions_and_validator_are_resolved(provided):
    actions = {rule.name: rule.action for rule in (*provided.key_rules, *provided.value_rules)}
    assert actions["auth-headers"] == "mask"
    assert actions["api-key-names"] == "hash"
    assert actions["card-number-fields"] == "partial"
    assert actions["cvv-fields"] == "remove"
    assert actions["email"] == "hash"

    validators = {rule.name: rule.validator for rule in provided.value_rules}
    assert validators["credit-card"] is luhn_valid
    assert validators["credit-card-19-grouped"] is luhn_valid
    assert validators["email"] is None


# --- key rule matching ------------------------------------------------------


@pytest.mark.parametrize(
    ("key_name", "scope", "expected_rule"),
    [
        # `exact` names ignore case, as HTTP header names do.
        ("Authorization", SCOPE_HEADERS, "auth-headers"),
        ("authorization", SCOPE_HEADERS, "auth-headers"),
        ("AUTHORIZATION", SCOPE_HEADERS, "auth-headers"),
        ("Set-Cookie", SCOPE_HEADERS, "auth-headers"),
        # scope: headers does not reach into bodies ...
        ("Authorization", SCOPE_BODY, None),
        # ... scope: body does not reach into headers ...
        ("password", SCOPE_BODY, "secret-fields"),
        ("password", SCOPE_HEADERS, None),
        # ... and scope: any covers both.
        ("X-Api-Key", SCOPE_HEADERS, "api-key-names"),
        ("x-api-key", SCOPE_HEADERS, "api-key-names"),
        ("api_key", SCOPE_BODY, "api-key-names"),
        ("ApiKey", SCOPE_BODY, "api-key-names"),
        # Case variants from input.ndjson line 27.
        ("Password", SCOPE_BODY, "secret-fields"),
        ("PASSWORD", SCOPE_BODY, "secret-fields"),
        ("Client_Secret", SCOPE_BODY, "secret-fields"),
        ("card_number", SCOPE_BODY, "card-number-fields"),
        ("cardNumber", SCOPE_BODY, "card-number-fields"),
        ("pan", SCOPE_BODY, "card-number-fields"),
        ("cvv", SCOPE_BODY, "cvv-fields"),
        # Look-alikes from input.ndjson line 48: the patterns are anchored.
        ("password_hint", SCOPE_BODY, None),
        ("passwordless", SCOPE_BODY, None),
        ("tokenizer", SCOPE_BODY, None),
        ("secret_santa", SCOPE_BODY, None),
        ("Content-Type", SCOPE_HEADERS, None),
    ],
)
def test_key_rule_lookup_on_the_provided_rules(provided, key_name, scope, expected_rule):
    rule = provided.find_key_rule(key_name, scope)
    assert (rule.name if rule else None) == expected_rule


def test_first_matching_key_rule_wins():
    rules = rules_from(
        """
        key_rules:
          - name: first
            scope: any
            match: { regex: '^token$' }
            action: hash
          - name: second
            scope: any
            match: { exact: [token] }
            action: mask
        """
    )
    assert rules.find_key_rule("token", SCOPE_BODY).name == "first"


def test_key_regex_without_anchors_matches_inside_the_name():
    # Anchoring is the rule author's decision; the loader does not add it.
    rules = rules_from(
        """
        key_rules:
          - name: anything-secret
            scope: body
            match: { regex: 'secret' }
            action: mask
        """
    )
    assert rules.find_key_rule("client_secret_v2", SCOPE_BODY).name == "anything-secret"


# --- value rules ------------------------------------------------------------


def test_patterns_use_ascii_word_boundaries():
    # With Python's Unicode default, \b sees no boundary between a Japanese
    # letter and a digit, and this card number would not be found.
    rules = rules_from(
        r"""
        value_rules:
          - name: card
            pattern: '\b\d{13,19}\b'
            action: partial
        """
    )
    match = rules.value_rules[0].pattern.search("カード4012888888881881です")
    assert match is not None and match.group() == "4012888888881881"


def test_patterns_treat_only_ascii_digits_as_digits():
    rules = rules_from(
        r"""
        value_rules:
          - name: digits
            pattern: '\d{4}'
            action: mask
        """
    )
    assert rules.value_rules[0].pattern.search("٤١١١") is None


def test_settings_are_optional_and_default_to_the_brief_values():
    rules = rules_from(
        """
        value_rules:
          - name: email
            pattern: '@'
            action: hash
        """
    )
    assert rules.settings == ActionSettings()
    assert rules.key_rules == ()


def test_settings_can_be_overridden():
    rules = rules_from(
        """
        settings:
          mask: { replacement: "[REDACTED]" }
          partial: { keep_last: 2, fill: "#" }
        value_rules:
          - name: email
            pattern: '@'
            action: hash
        """
    )
    assert rules.settings == ActionSettings(mask_replacement="[REDACTED]", keep_last=2, fill="#")


# --- invalid files must be rejected -----------------------------------------

# A minimal valid rule, appended to cases that are about something else.
VALID_VALUE_RULE = dedent(
    """
    value_rules:
      - name: email
        pattern: '@'
        action: hash
    """
)

# Whole documents (no version line is added to these).
INVALID_DOCUMENTS = {
    "not YAML": ("key_rules: [unclosed", "not valid YAML"),
    "empty file": ("", "expected a mapping"),
    "top level is a list": ("- a\n- b\n", "expected a mapping"),
    "version missing": (VALID_VALUE_RULE, "version"),
    "version unsupported": ("version: 2" + VALID_VALUE_RULE, "version"),
    "version is a boolean": ("version: yes" + VALID_VALUE_RULE, "version"),
}

INVALID_BODIES = {
    # The file parses, but would not redact anything.
    "no rules at all": ("settings: {}", "no rules"),
    "empty rule lists": ("key_rules: []\nvalue_rules: []", "no rules"),
    # Typos that would silently disable a rule if unknown fields were ignored.
    "unknown top-level field": (
        """
        value_rule:
          - name: email
            pattern: '@'
            action: hash
        """,
        "value_rule",
    ),
    "unknown rule field": (
        """
        value_rules:
          - name: email
            pattern: '@'
            actoin: hash
        """,
        "actoin",
    ),
    "unknown action": (
        """
        value_rules:
          - name: email
            pattern: '@'
            action: encrypt
        """,
        "action",
    ),
    "action is a list": (
        """
        value_rules:
          - name: email
            pattern: '@'
            action: [mask]
        """,
        "action",
    ),
    "missing pattern": (
        """
        value_rules:
          - name: email
            action: hash
        """,
        "pattern",
    ),
    "invalid regular expression": (
        """
        value_rules:
          - name: broken
            pattern: '(unclosed'
            action: mask
        """,
        "invalid regular expression",
    ),
    "pattern matches the empty string": (
        r"""
        value_rules:
          - name: greedy
            pattern: '\d*'
            action: mask
        """,
        "empty string",
    ),
    "unknown validator": (
        r"""
        value_rules:
          - name: card
            pattern: '\d{13,19}'
            validator: mod11
            action: partial
        """,
        "validator",
    ),
    "rule is not a mapping": ("value_rules:\n  - just-a-string", "expected a mapping"),
    "rules section is not a list": ("value_rules: { name: email }", "expected a list"),
    "missing name": (
        """
        value_rules:
          - pattern: '@'
            action: hash
        """,
        "name",
    ),
    "name is not a string": (
        """
        value_rules:
          - name: 123
            pattern: '@'
            action: hash
        """,
        "name",
    ),
    "duplicate rule name": (
        """
        key_rules:
          - name: same
            scope: any
            match: { exact: [token] }
            action: mask
        value_rules:
          - name: same
            pattern: '@'
            action: hash
        """,
        "duplicate",
    ),
    "unknown scope": (
        """
        key_rules:
          - name: k
            scope: query
            match: { exact: [token] }
            action: mask
        """,
        "scope",
    ),
    "missing scope": (
        """
        key_rules:
          - name: k
            match: { exact: [token] }
            action: mask
        """,
        "scope",
    ),
    "match has both exact and regex": (
        """
        key_rules:
          - name: k
            scope: any
            match: { exact: [token], regex: '^token$' }
            action: mask
        """,
        "exactly one",
    ),
    "match is empty": (
        """
        key_rules:
          - name: k
            scope: any
            match: {}
            action: mask
        """,
        "exactly one",
    ),
    "match has an unknown matcher": (
        """
        key_rules:
          - name: k
            scope: any
            match: { prefix: tok }
            action: mask
        """,
        "prefix",
    ),
    "exact list is empty": (
        """
        key_rules:
          - name: k
            scope: any
            match: { exact: [] }
            action: mask
        """,
        "exact",
    ),
    # YAML 1.1 reads a bare `on` as the boolean true, not as the text "on".
    "exact name is not a string": (
        """
        key_rules:
          - name: k
            scope: any
            match: { exact: [token, on] }
            action: mask
        """,
        "exact",
    ),
    "unknown settings section": ("settings: { redact: {} }" + VALID_VALUE_RULE, "redact"),
    "unknown settings field": (
        "settings: { mask: { text: x } }" + VALID_VALUE_RULE,
        "text",
    ),
    "empty mask replacement": (
        'settings: { mask: { replacement: "" } }' + VALID_VALUE_RULE,
        "replacement",
    ),
    "negative keep_last": (
        "settings: { partial: { keep_last: -1 } }" + VALID_VALUE_RULE,
        "keep_last",
    ),
    "keep_last is a boolean": (
        "settings: { partial: { keep_last: true } }" + VALID_VALUE_RULE,
        "keep_last",
    ),
    "keep_last is text": (
        'settings: { partial: { keep_last: "4" } }' + VALID_VALUE_RULE,
        "keep_last",
    ),
    # A longer fill would make the masked text grow on every pass.
    "fill longer than one character": (
        'settings: { partial: { fill: "**" } }' + VALID_VALUE_RULE,
        "fill",
    ),
    "unsupported hash algorithm": (
        "settings: { hash: { algorithm: md5 } }" + VALID_VALUE_RULE,
        "algorithm",
    ),
}


@pytest.mark.parametrize("case", INVALID_DOCUMENTS)
def test_invalid_document_is_rejected(case):
    text, expected_in_message = INVALID_DOCUMENTS[case]
    with pytest.raises(RulesError, match=expected_in_message):
        parse_rules(text)


@pytest.mark.parametrize("case", INVALID_BODIES)
def test_invalid_rules_are_rejected(case):
    body, expected_in_message = INVALID_BODIES[case]
    with pytest.raises(RulesError, match=expected_in_message):
        rules_from(body)


# PyYAML alone keeps the last of two equal keys without complaint, so each of
# these would load as a different rule set than the one a reader sees.
DUPLICATE_KEYS = {
    "action given twice in a rule": (
        """
        value_rules:
          - name: email
            pattern: '@'
            action: mask
            action: hash
        """,
        "action",
    ),
    "scope given twice in a key rule": (
        """
        key_rules:
          - name: k
            scope: headers
            scope: any
            match: { exact: [token] }
            action: mask
        """,
        "scope",
    ),
    "matcher given twice in an inline mapping": (
        """
        key_rules:
          - name: k
            scope: any
            match: { exact: [token], exact: [password] }
            action: mask
        """,
        "exact",
    ),
    "section given twice at the top level": (
        """
        value_rules:
          - name: email
            pattern: '@'
            action: hash
        value_rules:
          - name: other
            pattern: 'x'
            action: mask
        """,
        "value_rules",
    ),
    "setting given twice": (
        "settings: { partial: { keep_last: 4, keep_last: 0 } }" + VALID_VALUE_RULE,
        "keep_last",
    ),
}


@pytest.mark.parametrize("case", DUPLICATE_KEYS)
def test_duplicate_yaml_key_is_rejected(case):
    body, duplicated_key = DUPLICATE_KEYS[case]
    with pytest.raises(RulesError) as error:
        rules_from(body)
    message = str(error.value)
    assert "duplicate key" in message
    assert repr(duplicated_key) in message
    # The position helps whoever edits the file find the second occurrence.
    assert "line" in message


def test_duplicate_version_key_is_rejected():
    with pytest.raises(RulesError, match="duplicate key 'version'"):
        parse_rules("version: 1\nversion: 1" + VALID_VALUE_RULE)


def test_same_key_in_different_rules_is_not_a_duplicate():
    # Uniqueness is per mapping: every rule has its own `name` and `action`.
    rules = rules_from(
        """
        value_rules:
          - name: first
            pattern: 'a'
            action: mask
          - name: second
            pattern: 'b'
            action: mask
        """
    )
    assert rules.rule_names == ("first", "second")


def test_unhashable_yaml_key_is_a_rules_error_not_a_crash():
    # `? [a, b]` is YAML for a key that is a list.
    with pytest.raises(RulesError, match="not valid YAML"):
        parse_rules("version: 1\n? [a, b]\n: value\n")


def test_error_message_names_the_offending_rule():
    with pytest.raises(RulesError) as error:
        rules_from(
            """
            key_rules:
              - name: good
                scope: any
                match: { exact: [token] }
                action: mask
              - name: api-key-names
                scope: any
                match: { regex: '^api_key$' }
                action: hsah
            """
        )
    message = str(error.value)
    assert "key_rules[1]" in message
    assert "api-key-names" in message
    assert "hsah" in message


def test_missing_file_is_a_rules_error(tmp_path):
    with pytest.raises(RulesError, match="cannot read"):
        load_rules(tmp_path / "does-not-exist.yaml")


def test_file_that_is_not_utf8_is_a_rules_error(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_bytes(b"version: 1\nkey_rules: \xff\xfe\n")
    with pytest.raises(RulesError, match="cannot read"):
        load_rules(path)


def test_rule_set_cannot_be_modified_after_loading(provided):
    # The same RuleSet is shared by every stream, so it must be read-only.
    with pytest.raises(AttributeError):
        provided.key_rules = ()
    with pytest.raises(AttributeError):
        provided.key_rules[0].action = "remove"

"""Unit tests for the redaction actions and the Luhn validator."""

import hashlib
import re

import pytest

from redactor.actions import (
    ACTIONS,
    HASH,
    HASH_TAG,
    MASK,
    PARTIAL,
    REMOVE,
    STRICTEST_FIRST,
    ActionSettings,
    apply_action,
    luhn_valid,
    partial,
    sha256_digest,
)

DEFAULTS = ActionSettings()
BARE_DIGEST = re.compile(r"[0-9a-f]{64}")


# --- partial ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("4111111111111111", "************1111"),
        ("378282246310005", "***********0005"),
        # Separators count as characters: only the last four stay readable.
        ("4111 1111 1111 1111", "***************1111"),
        ("5555-5555-5555-4444", "***************4444"),
        ("12345", "*2345"),
    ],
)
def test_partial_keeps_only_the_last_four_characters(value, expected):
    assert partial(value, keep_last=4, fill="*") == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1234", "****"), ("123", "***"), ("7", "*"), ("", "")],
)
def test_partial_hides_a_short_value_completely(value, expected):
    # "Keep the last 4" of a 4-character value would reveal all of it.
    assert partial(value, keep_last=4, fill="*") == expected


def test_partial_with_keep_last_zero_hides_everything():
    # Guards against value[-0:], which is the whole string.
    assert partial("secret", keep_last=0, fill="*") == "******"


def test_partial_uses_the_configured_fill_and_length():
    assert partial("abcdefgh", keep_last=2, fill="#") == "######gh"


def test_partial_counts_characters_not_bytes():
    # Each of these characters takes two to four bytes in UTF-8.
    assert partial("😀😀😀😀😀ñüçé", keep_last=4, fill="*") == "*****ñüçé"


@pytest.mark.parametrize(
    "value",
    ["4111111111111111", "4111 1111 1111 1111", "1234", "12", "", "************1111"],
)
def test_partial_is_idempotent(value):
    once = partial(value, keep_last=4, fill="*")
    assert partial(once, keep_last=4, fill="*") == once


# --- hash: both forms ---------------------------------------------------------

# Standard SHA-256 test vector for "abc".
ABC_DIGEST = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_tagged_and_bare_digest_are_the_same_sha256():
    assert sha256_digest("abc", tagged=True) == "sha256:" + ABC_DIGEST
    assert sha256_digest("abc", tagged=False) == ABC_DIGEST


@pytest.mark.parametrize("tagged", [True, False])
def test_hash_encodes_non_ascii_text_as_utf8(tagged):
    expected = hashlib.sha256("tanaka@例え.jp".encode("utf-8")).hexdigest()
    assert sha256_digest("tanaka@例え.jp", tagged=tagged).endswith(expected)


@pytest.mark.parametrize("tagged", [True, False])
def test_hash_is_deterministic_so_equal_values_can_be_correlated(tagged):
    assert sha256_digest("a@b.com", tagged=tagged) == sha256_digest("a@b.com", tagged=tagged)
    assert sha256_digest("a@b.com", tagged=tagged) != sha256_digest("A@b.com", tagged=tagged)


@pytest.mark.parametrize("tagged", [True, False])
def test_hash_accepts_a_lone_surrogate_without_crashing(tagged):
    # json.loads('"\\ud83d"') produces this string; strict UTF-8 cannot encode it.
    result = sha256_digest("\ud83d", tagged=tagged)
    assert BARE_DIGEST.fullmatch(result.removeprefix(HASH_TAG))


# --- hash for a key rule: tagged, recognises its own output --------------------


@pytest.mark.parametrize("value", ["sk_live_abc123", "a@b.com", "", "****"])
def test_tagged_hash_is_idempotent(value):
    once = sha256_digest(value, tagged=True)
    assert sha256_digest(once, tagged=True) == once


def test_tagged_hash_does_not_trust_a_bare_64_hex_value():
    # A genuine API key can look exactly like a SHA-256 digest. It must be
    # hashed, not mistaken for a value that was already redacted.
    genuine_key = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    result = sha256_digest(genuine_key, tagged=True)
    assert genuine_key not in result
    assert result == HASH_TAG + hashlib.sha256(genuine_key.encode()).hexdigest()


@pytest.mark.parametrize(
    "near_miss",
    [
        "sha256:" + "A" * 64,  # upper-case digest
        "SHA256:" + "a" * 64,  # upper-case tag
        "sha256:" + "a" * 63,  # too short
        "sha256:" + "a" * 65,  # too long
        "sha256:" + "g" * 64,  # not hex
        "sha256:" + "a" * 64 + "\n",  # trailing newline (a `$` anchor would accept it)
        " sha256:" + "a" * 64,  # leading space
        "sha256:" + "a" * 64 + " and more",
    ],
)
def test_tagged_hash_only_recognises_an_exact_tagged_digest(near_miss):
    result = sha256_digest(near_miss, tagged=True)
    assert result != near_miss
    assert result.startswith(HASH_TAG)
    assert len(result) == len(HASH_TAG) + 64


# --- hash for a value rule: bare digest, nothing is ever skipped ---------------


def test_bare_hash_has_no_tag():
    result = sha256_digest("a@b.com", tagged=False)
    assert BARE_DIGEST.fullmatch(result)


@pytest.mark.parametrize(
    "looks_hashed",
    [
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",  # bare 64 hex
        "sha256:" + "a" * 64,  # the tagged form
    ],
)
def test_bare_hash_never_skips_a_value(looks_hashed):
    # A value rule only reaches this function with text its pattern matched.
    # Whatever that text looks like, it is hashed.
    result = sha256_digest(looks_hashed, tagged=False)
    assert result != looks_hashed
    assert result == hashlib.sha256(looks_hashed.encode()).hexdigest()


# --- luhn -------------------------------------------------------------------


@pytest.mark.parametrize(
    "number",
    [
        "4111111111111111",  # Visa test number
        "4012888888881881",
        "5555555555554444",  # Mastercard
        "378282246310005",  # American Express, 15 digits
        "30569309025904",  # Diners Club, 14 digits
        "6011111111111117",  # Discover
    ],
)
def test_luhn_accepts_valid_card_numbers(number):
    assert luhn_valid(number)


@pytest.mark.parametrize(
    "number",
    [
        "4111111111111112",  # last digit changed (input.ndjson line 4)
        "1705312800123456",  # a 16-digit request id (input.ndjson line 35)
        "1234567890123456",
    ],
)
def test_luhn_rejects_digit_runs_that_are_not_card_numbers(number):
    assert not luhn_valid(number)


@pytest.mark.parametrize(
    "formatted",
    ["4111 1111 1111 1111", "5555-5555-5555-4444", "3782 822463 10005"],
)
def test_luhn_ignores_spaces_and_hyphens(formatted):
    assert luhn_valid(formatted)


@pytest.mark.parametrize(
    "text",
    [
        "",  # an empty checksum is 0, which must not count as valid
        "    ",
        "----",
        "4111a11111111111",
        "4111.1111.1111.1111",
        "٤١١١١١١١١١١١١١١١",  # Arabic-Indic digits: str.isdigit() is True for these
        "²²²²",  # superscript digits: isdigit() is True, int() would raise
    ],
)
def test_luhn_rejects_text_that_is_not_ascii_digits(text):
    assert not luhn_valid(text)


# --- apply_action -----------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "value", "expected"),
    [
        (MASK, "hunter2", "****"),
        (PARTIAL, "4111111111111111", "************1111"),
        (HASH, "abc", "sha256:" + ABC_DIGEST),
        (REMOVE, "123", ""),
    ],
)
def test_apply_action_applies_the_named_action(action, value, expected):
    assert apply_action(action, value, DEFAULTS, tagged_hash=True) == expected


def test_apply_action_follows_the_settings_and_the_hash_form():
    settings = ActionSettings(mask_replacement="[REDACTED]", keep_last=2, fill="#")
    assert apply_action(MASK, "hunter2", settings, tagged_hash=True) == "[REDACTED]"
    assert apply_action(PARTIAL, "4111111111111111", settings, tagged_hash=True) == "##############11"
    assert apply_action(HASH, "abc", DEFAULTS, tagged_hash=False) == ABC_DIGEST


def test_strictness_order_ranks_every_action_exactly_once():
    assert STRICTEST_FIRST == (REMOVE, MASK, HASH, PARTIAL)
    assert set(STRICTEST_FIRST) == ACTIONS
    assert len(STRICTEST_FIRST) == len(ACTIONS)

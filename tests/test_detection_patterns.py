"""Tests for the detection patterns in rules.yaml: what they find and what they leave alone.

The engine tests check how rules are applied. These tests check the rules
themselves, against the real rules.yaml:

  * JWTs. The brief reports that the provided pattern "misses some JWTs seen
    in production samples". The pattern used the standard base64 alphabet
    (`+`, `/`, `=`), while the three parts of a JWT are base64url (`-`, `_`,
    no padding; RFC 7515).
  * Card numbers written in groups with spaces or hyphens, which the provided
    pattern (digits only) did not match. Detection needs both the structure
    of a card number and the Luhn check.
"""

import base64
import json
from pathlib import Path

import pytest

from redactor.actions import luhn_valid
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


def partial(value: str) -> str:
    """What the `partial` action writes: everything but the last 4 characters masked."""
    return "*" * (len(value) - 4) + value[-4:]


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


# --- card numbers -------------------------------------------------------------
#
# Two tests have to agree before anything is redacted. The structure says
# where a number starts and ends: 13 to 19 digits in a row, or one of the
# layouts cards are written in. The Luhn check says whether those digits are
# a card. Structure alone would redact every order number of the right shape.
# Luhn alone would accept whatever boundaries a loose pattern happened to
# pick, such as the first 16 digits of a longer number.


def grouped(number: str, layout: tuple[int, ...], separator: str = " ") -> str:
    """Write `number` in groups: ("4111111111111111", (4, 4, 4, 4)) -> "4111 1111 1111 1111"."""
    assert sum(layout) == len(number)
    groups, position = [], 0
    for size in layout:
        groups.append(number[position : position + size])
        position += size
    return separator.join(groups)


def with_wrong_check_digit(number: str) -> str:
    """The same number with its last digit changed, so that it fails Luhn."""
    return number[:-1] + str((int(number[-1]) + 1) % 10)


# Well-known test numbers of the card networks.
VISA = "4111111111111111"
MASTERCARD = "5555555555554444"
DISCOVER = "6011111111111117"
AMEX = "378282246310005"
AMEX_2 = "371449635398431"
DINERS = "30569309025904"
VISA_13 = "4222222222222"
# Two 19-digit numbers that pass Luhn. The first 16 digits of LONG_19 pass
# Luhn too; the first 16 digits of LONG_19_ONLY do not.
LONG_19 = "6304000000000000000"
LONG_19_ONLY = "6221261234567800003"

SIXTEEN = (4, 4, 4, 4)
AMEX_LAYOUT = (4, 6, 5)
DINERS_LAYOUT = (4, 6, 4)
NINETEEN = (4, 4, 4, 4, 3)

VISA_SPACES = grouped(VISA, SIXTEEN)
AMEX_SPACES = grouped(AMEX, AMEX_LAYOUT)

SUPPORTED = [
    # Digits only, 13 to 19 digits.
    VISA,
    MASTERCARD,
    DISCOVER,
    AMEX,
    AMEX_2,
    DINERS,
    VISA_13,
    LONG_19,
    LONG_19_ONLY,
    # 4-4-4-4
    VISA_SPACES,
    grouped(VISA, SIXTEEN, "-"),
    grouped(MASTERCARD, SIXTEEN),
    grouped(MASTERCARD, SIXTEEN, "-"),
    grouped(DISCOVER, SIXTEEN),
    # 4-6-5: American Express
    AMEX_SPACES,
    grouped(AMEX, AMEX_LAYOUT, "-"),
    grouped(AMEX_2, AMEX_LAYOUT),
    grouped(AMEX_2, AMEX_LAYOUT, "-"),
    # 4-6-4: Diners Club
    grouped(DINERS, DINERS_LAYOUT),
    grouped(DINERS, DINERS_LAYOUT, "-"),
    # 4-4-4-4-3: 19 digits
    grouped(LONG_19, NINETEEN),
    grouped(LONG_19, NINETEEN, "-"),
    grouped(LONG_19_ONLY, NINETEEN),
    grouped(LONG_19_ONLY, NINETEEN, "-"),
]


@pytest.mark.parametrize("card", SUPPORTED)
def test_every_supported_format_is_redacted(card):
    assert luhn_valid(card)
    assert redact_text(f"charge {card} today") == f"charge {partial(card)} today"


def test_sample_line_1_card_with_spaces():
    assert redact_sample_line(1)["body"]["note"] == "card ***************1111 on file"


def test_sample_line_6_card_with_hyphens():
    assert redact_sample_line(6)["body"]["message"] == (
        "please charge ***************4444 and send the receipt"
    )


def test_sample_line_36_american_express_with_spaces():
    assert redact_sample_line(36)["body"]["note"] == (
        "diners **********5904, discover ************1117, amex *************0005"
    )


def test_sample_line_44_cards_as_array_items():
    assert redact_sample_line(44)["body"] == ["************1111", "hello", "***************4444"]


# --- structure and Luhn must both hold ----------------------------------------


# Every supported format with its last digit changed. LONG_19 in groups is
# left out: its first 16 digits pass Luhn on their own, so with a wrong last
# digit it reads as a 16-digit card followed by three digits. That case is
# covered by test_sixteen_digits_followed_by_three_are_decided_by_luhn.
STRUCTURE_ONLY = [
    with_wrong_check_digit(card)
    for card in SUPPORTED
    if card not in (grouped(LONG_19, NINETEEN), grouped(LONG_19, NINETEEN, "-"))
]


@pytest.mark.parametrize("number", STRUCTURE_ONLY)
def test_the_right_structure_that_fails_luhn_is_left_alone(number):
    assert not luhn_valid(number)
    text = f"charge {number} today"
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "number",
    [
        grouped(VISA, (8, 8)),
        grouped(VISA, (4, 8, 4)),
        grouped(VISA, (6, 10)),
        grouped(VISA_13, (4, 4, 4, 1)),
        grouped(AMEX, (5, 5, 5)),
        " ".join(VISA),  # one digit at a time
        grouped(VISA, SIXTEEN, "  "),  # two spaces
        grouped(VISA, SIXTEEN, " - "),
        grouped(VISA, SIXTEEN, "."),
    ],
)
def test_digits_that_pass_luhn_in_another_layout_are_left_alone(number):
    # The price of deciding boundaries by structure: only the listed layouts
    # are read as one number. A card typed in an unusual way is not found.
    assert luhn_valid("".join(char for char in number if char.isdigit()))
    text = f"charge {number} today"
    assert redact_text(text) == text


# Numbers with the structure of a card that are something else. Luhn is what
# keeps them: it rejects nine such numbers in ten, and the tenth is a
# documented false positive. These examples are all among the nine.
LOOK_ALIKES = [
    ("a timestamp in microseconds", "request id 1705312800123456 took 12ms", "1705312800123456"),
    ("a compact timestamp", "order placed at 20250115100035", "20250115100035"),
    ("an order number in groups", "order ORD-2025-0115-0001-2346 shipped", "2025-0115-0001-2346"),
    ("an order number, digits only", "your order 9000100020003000 is on its way", "9000100020003000"),
    ("the digits of an IBAN", "pay to DE89 3704 0044 0532 0130 00", "3704 0044 0532 0130"),
]


@pytest.mark.parametrize(
    ("text", "digits"),
    [case[1:] for case in LOOK_ALIKES],
    ids=[case[0] for case in LOOK_ALIKES],
)
def test_order_numbers_and_timestamps_that_fail_luhn_are_left_alone(text, digits):
    assert digits in text and not luhn_valid(digits)
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "at 2025-01-15T10:00:35Z",
        "at 2025-01-15 10:00:35.123456",
        "phone +1 (415) 555-0132, alt 0800 123 4567",
        "id 550e8400-e29b-41d4-a716-446655440000",
        "pages 12-15 of 2024-2025",
    ],
)
def test_dates_phones_and_ids_have_no_card_structure(text):
    assert redact_text(text) == text


# --- a long number is not redacted in part ------------------------------------


@pytest.mark.parametrize("number", [LONG_19, LONG_19_ONLY])
@pytest.mark.parametrize("separator", [" ", "-"])
def test_a_19_digit_number_in_groups_is_redacted_whole(number, separator):
    card = grouped(number, NINETEEN, separator)
    redacted = redact_text(f"charge {card} today")
    assert redacted == f"charge {partial(card)} today"
    # Not "the first 16 digits and a tail": the last four characters are all
    # that is left of the number.
    assert sum(char.isdigit() for char in redacted) == 3


@pytest.mark.parametrize(
    "number",
    [
        "12345678901234567894",  # 20 digits that pass Luhn
        "5555555555554444000000",  # 22 digits that pass Luhn
        VISA + "12345678",  # 24 digits that start with a valid card
        VISA + MASTERCARD,  # 32 digits: two valid cards with nothing between them
    ],
)
def test_more_than_19_digits_in_a_row_are_left_alone(number):
    # No card number is this long. Luhn would accept the first two as a
    # whole and the last two by their first 16 digits; the structure does not.
    assert luhn_valid(number) or luhn_valid(number[:16])
    text = f"reference {number} stored"
    assert redact_text(text) == text


# --- a CVV is not read as part of the card ------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"card {VISA_SPACES} 123", f"card {partial(VISA_SPACES)} 123"),
        (f"card {grouped(VISA, SIXTEEN, '-')} 123", f"card {partial(VISA_SPACES)} 123"),
        (f"card {VISA} 123", f"card {partial(VISA)} 123"),
        (f"amex {AMEX_SPACES} 1234", f"amex {partial(AMEX_SPACES)} 1234"),
        (f"amex {AMEX} 1234", f"amex {partial(AMEX)} 1234"),
        (f"diners {grouped(DINERS, DINERS_LAYOUT)} 123", "diners ************5904 123"),
        (f"card {VISA_SPACES} 12/26", f"card {partial(VISA_SPACES)} 12/26"),
        (f"card {VISA_SPACES} 12-26", f"card {partial(VISA_SPACES)} 12-26"),
        (f"card {VISA_SPACES} exp 2026", f"card {partial(VISA_SPACES)} exp 2026"),
    ],
)
def test_a_cvv_or_expiry_after_the_card_stays_outside_the_match(text, expected):
    assert redact_text(text) == expected


def count_card_redactions(text: str) -> tuple[str, int]:
    """Redact `text`; return the result and the number of card redactions counted."""
    redactor = Redactor(RULES)
    result = json.loads(redactor.redact(json.dumps({"note": text})))["note"]
    return result, redactor.counts["credit-card"] + redactor.counts["credit-card-19-grouped"]


def test_sixteen_digits_followed_by_three_are_decided_by_luhn():
    # "dddd dddd dddd dddd ddd" has two readings: one 19-digit number, or a
    # 16-digit card and its CVV. The structure cannot tell them apart. Each
    # reading is checked with Luhn, and what passes is redacted.

    # Only the first 16 digits pass: a card and a CVV.
    assert luhn_valid(VISA) and not luhn_valid(VISA + "123")
    assert count_card_redactions(f"{VISA_SPACES} 123") == (f"{partial(VISA_SPACES)} 123", 1)

    # Only the 19 digits pass: one long number, redacted whole.
    assert luhn_valid(LONG_19_ONLY) and not luhn_valid(LONG_19_ONLY[:16])
    long_number = grouped(LONG_19_ONLY, NINETEEN)
    assert count_card_redactions(long_number) == (partial(long_number), 1)

    # Both pass: still one redaction, and it covers all 19 digits.
    assert luhn_valid(LONG_19) and luhn_valid(LONG_19[:16])
    long_number = grouped(LONG_19, NINETEEN)
    assert count_card_redactions(long_number) == (partial(long_number), 1)

    # Neither passes: nothing is redacted.
    neither = grouped(with_wrong_check_digit(VISA), SIXTEEN) + " 124"
    assert not luhn_valid(neither) and not luhn_valid(neither[:19])
    assert count_card_redactions(neither) == (neither, 0)

    # A 19-digit number with a wrong last digit whose first 16 digits pass:
    # by the same rule this is a card followed by three digits.
    mistyped = grouped(with_wrong_check_digit(LONG_19), NINETEEN)
    assert not luhn_valid(mistyped) and luhn_valid(mistyped[:19])
    assert count_card_redactions(mistyped) == (f"{partial(mistyped[:19])} 001", 1)


# --- digits next to a card ----------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Digits before the card. The first candidate ("2024 4111 1111 1111")
        # has the right structure and fails Luhn; the card starts inside it.
        (f"paid 2024 {VISA_SPACES} ok", f"paid 2024 {partial(VISA_SPACES)} ok"),
        (f"qty 12 {VISA_SPACES}", f"qty 12 {partial(VISA_SPACES)}"),
        # Two cards separated by one space. Written in groups, the groups in
        # the middle ("1111 1111 1111 5555", ...) are candidates too; one of
        # them passes Luhn, so the two cards merge into one redaction. That
        # hides the first card's last four digits as well: more, never less.
        (
            f"{VISA_SPACES} {grouped(MASTERCARD, SIXTEEN)}",
            partial(f"{VISA_SPACES} {grouped(MASTERCARD, SIXTEEN)}"),
        ),
        (f"{VISA} {MASTERCARD}", f"{partial(VISA)} {partial(MASTERCARD)}"),
        # A card followed by another group of four digits. A valid card is
        # never left in place because of what stands next to it.
        (f"{VISA_SPACES} 1111", f"{partial(VISA_SPACES)} 1111"),
    ],
)
def test_digits_next_to_a_card_do_not_hide_it(text, expected):
    assert redact_text(text) == expected


# --- idempotency --------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [f"session {SAMPLE_TOKEN} expired", f"Bearer {SAMPLE_TOKEN_SHORT}"]
    + [f"charge {card} today" for card in SUPPORTED]
    + [
        f"card {VISA_SPACES} 123",
        f"amex {AMEX_SPACES} 1234",
        f"{VISA_SPACES} {grouped(MASTERCARD, SIXTEEN)}",
        f"paid 2024 {VISA_SPACES} ok",
        f"{VISA_SPACES} 1111",
    ],
)
def test_a_second_run_changes_nothing(text):
    first = redact_text(text)
    assert first != text
    assert redact_text(first) == first


def test_a_card_followed_by_eleven_more_digits_is_stable():
    # The case a first, looser pattern got wrong: it read the four digits
    # that `partial` keeps, together with the digits after them, as a new
    # number on the second run. With defined structures they are no candidate.
    for number in range(1000):
        tail = f" 17053128{number:03d}"
        first = redact_text(VISA_SPACES + tail)
        assert first == partial(VISA_SPACES) + tail
        assert redact_text(first) == first


def test_a_card_whose_last_group_also_starts_a_card_is_stable():
    # The reported case: "1111 3129 3741 1406" is a valid card of its own,
    # beginning with the four digits `partial` keeps of the first card. Both
    # are found on the first run and merged into one redaction.
    original = "4111 1111 1111 1111 3129 3741 1406"
    assert luhn_valid("4111 1111 1111 1111") and luhn_valid("1111 3129 3741 1406")
    once = redact_text(original)
    assert once == "*" * 30 + "1406"
    twice = redact_text(once)
    assert twice == once


# `partial` keeps the last four digits of a card. If the card is followed by
# exactly the groups that complete the layout of another card, those four
# digits and the groups after them are a candidate too, and one such candidate
# in ten passes Luhn. When the card is written in groups, that candidate is
# already found on the first run (the test above), and the output is stable.
STABLE_FAMILIES = {
    "a card and three groups of four": VISA_SPACES + " 2222 3333 {:04d}",
    "a card, a group of six and a group of five": VISA_SPACES + " 822463 1{:04d}",
    "hyphens": grouped(MASTERCARD, SIXTEEN, "-") + "-2222-3333-{:04d}",
}


@pytest.mark.parametrize("template", STABLE_FAMILIES.values(), ids=STABLE_FAMILIES.keys())
def test_a_second_run_changes_nothing_when_the_kept_digits_are_a_group(template):
    for number in range(1000):
        first = redact_text(template.format(number))
        assert redact_text(first) == first


# Known limitation. When the kept four digits are not a group of their own in
# the input (a card written without separators, or an American Express number,
# whose last group has five digits), there is no word boundary in front of them
# on the first run, so they begin no candidate. Once the digits before them are
# masked there is one, and the second run finds the candidate.
#
# The tool cannot tell its own output from input that looks the same. The
# only way to stop this would be to refuse a match that follows a run of fill
# characters, and that would leave a real card readable in such an input,
# which is the worse mistake. The tests pin down what does hold: the second
# run can only hide more, never reveal, and the output is stable after it.
SECOND_RUN_FAMILIES = {
    "a card without separators and three groups of four": VISA + " 2222 3333 {:04d}",
    "a 13-digit card and three groups of four": VISA_13 + " 2222 3333 {:04d}",
    "American Express and three groups of four": AMEX_SPACES + " 2222 3333 {:04d}",
}


@pytest.mark.parametrize("template", SECOND_RUN_FAMILIES.values(), ids=SECOND_RUN_FAMILIES.keys())
def test_known_limitation_a_second_run_can_only_hide_more(template):
    changed = 0
    for number in range(1000):
        first = redact_text(template.format(number))
        second = redact_text(first)
        if second != first:
            changed += 1
            # Same length, and every character either stayed or became a fill character.
            assert len(second) == len(first)
            assert all(new in (old, "*") for old, new in zip(first, second))
            # A third run changes nothing.
            assert redact_text(second) == second
    # In each family the last digit runs through 0 to 9, and exactly one of
    # ten passes Luhn: one input in ten changes again.
    assert changed == 100


@pytest.mark.parametrize(
    "card",
    [
        VISA_SPACES,
        grouped(MASTERCARD, SIXTEEN, "-"),
        AMEX_SPACES,
        grouped(DINERS, DINERS_LAYOUT),
        grouped(LONG_19_ONLY, NINETEEN),
        VISA,
    ],
)
@pytest.mark.parametrize("stars", [1, 9, 40])
def test_a_card_right_after_fill_characters_is_still_redacted(card, stars):
    # Text that looks like the tail of a value this tool masked is input like
    # any other: "*********4111 1111 1111 1111" holds a card.
    prefix = "*" * stars
    assert redact_text(prefix + card) == prefix + partial(card)

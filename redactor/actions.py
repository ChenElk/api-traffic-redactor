"""Redaction actions and value validators.

Everything in this module is a pure function: text in, text out. It knows
nothing about YAML, JSON or rule matching, and it contains no rule names.
Keeping the security-relevant transformations this small makes them easy to
test and to reason about.

Idempotency contract: an action applied to its own output changes nothing.
    mask     always returns the same constant.
    partial  keeps the length and the last characters, so a second pass is a no-op.
    hash     depends on what triggered it, see sha256_digest.
    remove   leaves nothing behind to process again.
"""

import hashlib
import re
from dataclasses import dataclass

MASK = "mask"
PARTIAL = "partial"
HASH = "hash"
REMOVE = "remove"
ACTIONS = frozenset({MASK, PARTIAL, HASH, REMOVE})

# Actions from strictest to most permissive, ordered by how much of the
# original value they leave behind: nothing, a constant, a digest that can be
# linked and guessed, real characters. When several value rules match
# overlapping text, the strictest action is applied to all of it.
STRICTEST_FIRST = (REMOVE, MASK, HASH, PARTIAL)

# A digest produced for a key rule is this tag followed by 64 lowercase hex digits.
HASH_TAG = "sha256:"
_TAGGED_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class ActionSettings:
    """Tunable parameters of the actions (the `settings:` block of rules.yaml).

    Attributes:
        mask_replacement: Text that replaces a masked value.
        keep_last: How many trailing characters `partial` leaves readable.
        fill: The single character `partial` writes over the hidden part.
    """

    mask_replacement: str = "****"
    keep_last: int = 4
    fill: str = "*"


def partial(value: str, keep_last: int, fill: str) -> str:
    """Hide all of `value` except its last `keep_last` characters.

    The result always has the same length as the input. That is what makes the
    action idempotent: masking "************1111" again yields the same text.

    A value of `keep_last` characters or fewer is hidden completely. Read
    literally, "keep the last 4" would return a 4-character value such as
    "1234" untouched, which redacts nothing.

    Args:
        value: The sensitive text.
        keep_last: Number of trailing characters to keep (0 or more).
        fill: One character used for every hidden position.
    """
    hidden = len(value) - keep_last
    if hidden <= 0:
        return fill * len(value)
    # Slice from the front. value[-keep_last:] looks equivalent but breaks for
    # keep_last == 0, where value[-0:] is the whole string.
    return fill * hidden + value[hidden:]


def sha256_digest(value: str, *, tagged: bool) -> str:
    """Replace `value` with the SHA-256 digest of its UTF-8 bytes.

    The caller chooses the output form, because the two kinds of rule have
    different idempotency problems:

    tagged=True, for a key rule. Returns "sha256:" + 64 hex digits.
        A key rule matches the *name* of a key, so on a second run it fires
        again and now sees the digest. The action must recognise its own
        output or it would hash the hash. A bare digest cannot be recognised
        safely: a genuine API key can also be exactly 64 hex characters, and
        treating it as "already hashed" would write it out in clear. The tag
        makes our output a distinct format. A value is left untouched only if
        it is *exactly* a tagged digest; a bare 64-hex string, an upper-case
        digest or a tagged digest with anything appended is hashed normally.

    tagged=False, for a value rule. Returns the bare 64 hex digits.
        A value rule matches *content*. Its digest normally no longer matches
        the pattern (a digest is not an e-mail address), so the rule does not
        fire again and nothing needs recognising. No value is ever skipped.
        This holds only while no value pattern in the rules file matches a
        hex digest; a rules file is responsible for that.

    Security limitations (see the README for the full discussion):
      * The tag is not authenticated. A value that already has the exact
        tagged form passes through a key rule unchanged, so anyone can forge
        something that looks redacted.
      * SHA-256 is unsalted and unkeyed. Equal inputs give equal digests (this
        is what allows correlation), and guessable inputs such as e-mail
        addresses can be recovered by hashing candidates and comparing.

    Args:
        value: The sensitive text.
        tagged: True for the tagged, self-recognising form; False for a bare digest.
    """
    if tagged and _TAGGED_DIGEST.fullmatch(value):
        return value
    # "surrogatepass": a JSON escape such as "\ud83d" decodes to a lone
    # surrogate, which strict UTF-8 refuses to encode. Hashing must never be
    # the reason a record cannot be processed.
    digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    return HASH_TAG + digest if tagged else digest


def luhn_valid(text: str) -> bool:
    """Tell whether the digits in `text` pass the Luhn checksum.

    Used to separate real card numbers from arbitrary digit runs: a random
    number passes only one time in ten. Spaces and hyphens are skipped so that
    "4111 1111 1111 1111" and "4111-1111-1111-1111" validate like the plain
    number. Any other non-digit character makes the text invalid.

    Length is not checked here; the rule's pattern decides how many digits a
    candidate has.
    """
    digits = []
    for char in text:
        # Compare against ASCII explicitly. str.isdigit() also accepts
        # characters such as "²" or Arabic-Indic digits.
        if "0" <= char <= "9":
            digits.append(ord(char) - ord("0"))
        elif char not in " -":
            return False
    if not digits:
        # An empty sum is 0, and 0 % 10 == 0 would wrongly pass.
        return False

    total = 0
    # Walk from the rightmost digit and double every second one. A doubled
    # digit above 9 contributes the sum of its two digits, which equals
    # subtracting 9.
    for position, digit in enumerate(reversed(digits)):
        if position % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# Validators a value rule may name in rules.yaml (`validator: luhn`).
VALIDATORS = {"luhn": luhn_valid}


def apply_action(action: str, value: str, settings: ActionSettings, *, tagged_hash: bool) -> str:
    """Return the text that replaces `value` under `action`.

    `remove` returns an empty string, which is exactly "delete the matched
    text" for a value rule. For a key rule the engine goes one step further
    and drops the whole key; that is a structural change, so it lives there.

    Args:
        action: One of ACTIONS.
        value: The sensitive text.
        settings: Parameters for mask and partial.
        tagged_hash: Output form of `hash` (see sha256_digest): True when a
            key rule triggered the action, False for a value rule. Ignored by
            the other actions.

    Raises:
        ValueError: If `action` is not a known action. The rules loader rejects
            unknown actions, so this indicates a programming error.
    """
    if action == MASK:
        return settings.mask_replacement
    if action == PARTIAL:
        return partial(value, settings.keep_last, settings.fill)
    if action == HASH:
        return sha256_digest(value, tagged=tagged_hash)
    if action == REMOVE:
        return ""
    raise ValueError(f"unknown action: {action!r}")

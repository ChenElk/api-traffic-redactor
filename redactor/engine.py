"""The redaction engine: one JSON record in, one JSON record out.

The engine decides *where* to redact. *How* a value is redacted lives in
actions.py and *which* rules exist comes from rules.py. Nothing here names a
rule, a field or a pattern: all of that comes from the RuleSet. The engine
knows nothing about files, lines or HTTP; those belong to the streaming layer.

How a record is processed:

1. Decode the text with the standard json module. Two hooks keep what a plain
   decode-and-dump would silently change: objects become lists of (key, value)
   pairs, so key order and duplicate keys survive, and numbers stay as the
   exact text they had (`10.50` is not rewritten as `10.5`).
2. Walk the decoded tree once. For every key, ask the key rules (they look at
   the *name*). A string that no key rule claimed is given to the value rules
   (they look at the *content*).
3. The same walk writes the output text. If nothing was redacted, the original
   text is returned unchanged, byte for byte.

Fail closed: when the engine can see structure it is unable to inspect safely
(broken JSON holding a sensitive key, content nested beyond the limit), it
raises RecordError instead of letting the record through.
"""

import enum
import json
import re
from collections import Counter
from urllib.parse import quote_plus, unquote_plus

from redactor.actions import REMOVE, STRICTEST_FIRST, apply_action
from redactor.rules import SCOPE_BODY, SCOPE_HEADERS, KeyRule, RuleSet, ValueRule

REASON_INVALID_JSON = "invalid_json"
REASON_INVALID_EMBEDDED_JSON = "invalid_embedded_json"
REASON_TOO_DEEP = "too_deep"

# How many times content found *inside a string* is decoded again (JSON in a
# string, a form field holding JSON, ...). The limit bounds the work one
# record can cause. Plain text at the limit is still scanned by the value
# rules; structure at the limit is refused, see Redactor._redact_string.
MAX_STRING_NESTING = 5

_LOOKS_LIKE_JSON = re.compile(r"[ \t\r\n]*[{\[]")
# A quoted name followed by a colon: how a key is written in JSON, and in the
# single-quoted text Python prints for a dict.
_QUOTED_NAME = re.compile(r"""["']([^"']*)["']\s*:""")
_WHITESPACE = re.compile(r"\s")
_SURROGATE = re.compile("[\ud800-\udfff]")
# Characters left unescaped when a form value is re-encoded, so that `****`
# and `sha256:...` stay readable. Both are legal in a query string.
_FORM_SAFE_CHARACTERS = "*:"


class RecordError(ValueError):
    """A record that cannot be redacted safely.

    The caller decides what to emit instead of the record. `reason` is one of
    the fixed REASON_* codes. Neither it nor the exception message ever
    contains input data, so the exception is safe to log.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _Object(list):
    """A decoded JSON object: its (key, value) pairs in input order.

    A dict would keep only the last of two equal keys, and the earlier value
    would vanish from the output.
    """


class _Number(str):
    """A decoded JSON number, kept as the exact text it had in the input.

    Turning it into a float would rewrite `10.50` as `10.5` and `1e3` as
    `1000.0`; turning a huge integer into an int can even raise.
    """


def _reject_constant(name: str):
    # Python's json accepts NaN, Infinity and -Infinity, which are not JSON.
    raise ValueError("non-standard JSON constant")


_DECODER = json.JSONDecoder(
    object_pairs_hook=_Object,
    parse_int=_Number,
    parse_float=_Number,
    parse_constant=_reject_constant,
)
# ensure_ascii=False writes "Zürich" as it was, not as "Z\u00fcrich".
_encode_string = json.JSONEncoder(ensure_ascii=False).encode
_LITERALS = {True: "true", False: "false", None: "null"}


class _Location(enum.Enum):
    """Where in a record the walk currently is. Decides the scope of key names."""

    ROOT = enum.auto()  # the record itself
    RESPONSE = enum.auto()  # the object under the top-level "response" key
    HEADERS = enum.auto()  # the "headers" object of the request or the response
    BODY = enum.auto()  # everywhere else


def _child_location(location: _Location, key: str) -> _Location:
    """Location of the value stored under `key` in an object at `location`.

    The record layout is the only schema the engine knows: `headers` and
    `response.headers` hold HTTP headers. Every other key name, at any depth,
    is a body name. An object that merely happens to be called "headers"
    somewhere inside a body is therefore body scope.
    """
    if location is _Location.ROOT:
        if key == "headers":
            return _Location.HEADERS
        if key == "response":
            return _Location.RESPONSE
    elif location is _Location.RESPONSE:
        if key == "headers":
            return _Location.HEADERS
    elif location is _Location.HEADERS:
        return _Location.HEADERS
    return _Location.BODY


class Redactor:
    """Applies a RuleSet to JSON records, one record at a time.

    A Redactor keeps running counts, so use one per input stream. It is not
    thread-safe. The RuleSet is read-only and can be shared.

    Attributes:
        counts: Number of redactions per rule name, for all records processed
            so far. Every rule is present, with 0 if it never fired. A
            redaction is counted only when it changed the value, so running
            the tool on its own output reports zeros.
    """

    def __init__(self, rules: RuleSet):
        self._rules = rules
        self._settings = rules.settings
        # Each value rule with its priority for overlapping matches: stricter
        # action first, then position in the rules file. Lower sorts first.
        self._value_rules = [
            (rule, (STRICTEST_FIRST.index(rule.action), order))
            for order, rule in enumerate(rules.value_rules)
        ]
        self.counts: Counter[str] = Counter({name: 0 for name in rules.rule_names})
        # Redactions of the record being processed. Merged into `counts` only
        # when the record succeeds, and also the test for "was anything changed".
        self._record_counts: Counter[str] = Counter()

    def redact(self, line: str) -> str:
        """Redact one JSON record.

        Args:
            line: One JSON value as text (normally an object describing an
                HTTP transaction, but any valid JSON is accepted).

        Returns:
            The redacted record as compact JSON, which can always be encoded
            as UTF-8. If nothing had to be redacted, `line` itself is
            returned unchanged.

        Raises:
            RecordError: If the record cannot be redacted safely: it is not
                valid JSON, it is nested too deeply, or a string inside it
                holds structure that cannot be inspected. `counts` is left as
                it was.
        """
        self._record_counts = Counter()
        try:
            document = _DECODER.decode(line)
        except RecursionError:
            raise RecordError(REASON_TOO_DEEP) from None
        except ValueError:
            # `from None`: the original JSONDecodeError carries the whole
            # input in its `doc` attribute and must not travel with ours.
            raise RecordError(REASON_INVALID_JSON) from None

        try:
            redacted = self._write(document, _Location.ROOT, 0)
        except RecursionError:
            # The walk is recursive, so a record nested hundreds of levels
            # deep exhausts the Python stack. Refuse it rather than crash.
            raise RecordError(REASON_TOO_DEEP) from None

        if not self._record_counts:
            # Re-encoding can respell escapes (`\u0040` becomes `@`) and drops
            # whitespace between tokens. An untouched record keeps its bytes.
            return line
        self.counts.update(self._record_counts)
        # The JSON escape "\ud83d" decodes to a lone surrogate, a character
        # UTF-8 cannot represent, and the encoder above writes it back raw.
        # Spell each one as a \uXXXX escape again so the output can be written.
        return _SURROGATE.sub(lambda match: f"\\u{ord(match.group()):04x}", redacted)

    # --- walking the tree and writing the output ----------------------------

    def _write(self, node, location: _Location, depth: int) -> str:
        """Return the JSON text of `node` with redactions applied.

        Args:
            node: A decoded JSON value.
            location: Where `node` sits in the record (for key-rule scopes).
            depth: How many layers of string content were decoded to get here.
        """
        kind = type(node)
        if kind is str:
            return _encode_string(self._redact_string(node, depth))
        if kind is _Number:
            # Value rules look at string content only. Scanning numbers would
            # turn one timestamp in ten (those that happen to pass Luhn) into
            # a masked string and break the consumer's schema.
            return str(node)
        if kind is _Object:
            return self._write_object(node, location, depth)
        if kind is list:
            inner = location if location is _Location.HEADERS else _Location.BODY
            return "[" + ",".join([self._write(item, inner, depth) for item in node]) + "]"
        return _LITERALS[node]

    def _write_object(self, pairs: _Object, location: _Location, depth: int) -> str:
        scope = SCOPE_HEADERS if location is _Location.HEADERS else SCOPE_BODY
        members = []
        for key, value in pairs:
            rule = self._rules.find_key_rule(key, scope)
            if rule is None:
                written = self._write(value, _child_location(location, key), depth)
            elif rule.action == REMOVE:
                # The member is simply not written. Commas are added when the
                # members are joined, so removing the first or last one is safe.
                self._count(rule)
                continue
            else:
                written = self._write_under_key_rule(value, rule)
            members.append(_encode_string(key) + ":" + written)
        return "{" + ",".join(members) + "}"

    def _write_under_key_rule(self, node, rule: KeyRule) -> str:
        """Write `node`, the value of a key that `rule` matched.

        The rule owns everything below the key: value rules are not consulted
        and nested key names are not matched again. Arrays and objects keep
        their shape and every string or number inside them is redacted.
        `null`, `true`, `false` and the empty string hold nothing to hide and
        are kept, which also keeps "no password was sent" visible.
        """
        kind = type(node)
        if kind is str:
            return _encode_string(self._apply(rule, node))
        if kind is _Number:
            # A masked number is no longer a number, so it is written as a
            # string. This is always a change, whatever the replacement.
            self._count(rule)
            return _encode_string(
                apply_action(rule.action, str(node), self._settings, tagged_hash=True)
            )
        if kind is _Object:
            members = [
                _encode_string(key) + ":" + self._write_under_key_rule(value, rule)
                for key, value in node
            ]
            return "{" + ",".join(members) + "}"
        if kind is list:
            return "[" + ",".join([self._write_under_key_rule(item, rule) for item in node]) + "]"
        return _LITERALS[node]

    # --- string content -----------------------------------------------------

    def _redact_string(self, text: str, depth: int) -> str:
        """Redact the content of one string that no key rule claimed.

        A string can carry structure of its own, and key rules can only see
        names once that structure is decoded:
          * JSON in a string:      "{\"token\":\"abc\"}"
          * a form or query string: "email=a%40b.com&password=x", "/reset?token=abc"
        Everything else, and whatever is left after the steps above, is free
        text and is scanned by the value rules.

        `depth` counts the decoding layers above this string. At
        MAX_STRING_NESTING nothing is decoded any more. Free text there is
        scanned as usual, but structure that would have needed decoding makes
        the record unsafe to emit, and the two steps below raise RecordError.
        """
        embedded = self._redact_embedded_json(text, depth)
        if embedded is not None:
            return embedded
        text = self._redact_form(text, depth)
        return self._redact_text(text)

    def _redact_embedded_json(self, text: str, depth: int) -> str | None:
        """Redact `text` as a JSON document, or return None if it is plain text.

        Only objects and arrays count. A string holding `42` or `true` is
        valid JSON too, but has no keys worth decoding it for.

        Raises:
            RecordError: If `text` is JSON that cannot be inspected: it is
                broken and shows a key that a key rule targets, or it sits at
                the nesting limit.
        """
        if _LOOKS_LIKE_JSON.match(text) is None:
            return None
        try:
            document = _DECODER.decode(text)
        except ValueError:
            # It starts like JSON but does not parse: truncated, or simply
            # text that begins with a bracket, such as "[INFO] started".
            # Value rules can still scan it as text. Key rules cannot be
            # applied without the structure, so if a key they target is
            # visible, its value would go out unredacted.
            if self._shows_key_rule_target(text):
                raise RecordError(REASON_INVALID_EMBEDDED_JSON) from None
            return None

        if depth >= MAX_STRING_NESTING:
            # Valid JSON we are not allowed to open. Its keys were never
            # checked against the key rules.
            raise RecordError(REASON_TOO_DEEP)

        before = self._record_counts.total()
        written = self._write(document, _Location.BODY, depth + 1)
        # Same rule as for a whole record: untouched content keeps its text.
        return written if self._record_counts.total() != before else text

    def _shows_key_rule_target(self, broken_json: str) -> bool:
        """Tell whether unparseable JSON shows a key that a key rule would redact.

        Backslashes are dropped first, so that a key of JSON nested in a
        string, written as \\"password\\":, is seen as "password":.
        """
        for name in _QUOTED_NAME.findall(broken_json.replace("\\", "")):
            if self._rules.find_key_rule(name, SCOPE_BODY) is not None:
                return True
        return False

    def _redact_form(self, text: str, depth: int) -> str:
        """Redact `name=value&name=value` pairs; return `text` if nothing changed.

        Handles a form-encoded body and the query string of a URL or path;
        _split_form finds where the pairs are. Field names are checked against
        the key rules (body scope) and values are percent-decoded before they
        are inspected, so `bob%40example.com` is recognised as an e-mail
        address.

        Raises:
            RecordError: At the nesting limit, if a field would have needed
                decoding: a key rule targets its name, or its value is JSON.
        """
        parts = _split_form(text)
        if parts is None:
            return text
        head, query, tail = parts

        at_limit = depth >= MAX_STRING_NESTING
        changed = False
        pairs = []
        for pair in query.split("&"):
            raw_name, equals, raw_value = pair.partition("=")
            if not equals or not raw_name:
                pairs.append(pair)
                continue

            rule = self._rules.find_key_rule(unquote_plus(raw_name), SCOPE_BODY)
            value = unquote_plus(raw_value)

            if at_limit:
                # The nesting limit is reached: this field is not decoded any
                # further, so it has to be either harmless or refused.
                #   * A key rule targets the field name: refuse. The value
                #     should have been redacted, and we may not open it.
                #   * The value is JSON: refuse. At the limit the call below
                #     never redacts anything. It raises RecordError for JSON
                #     and returns None for plain text, and it is called only
                #     for that check.
                #   * Anything else: keep the pair as it is. Being a "form" is
                #     only a guess (no spaces and an "="), so an ordinary
                #     string must not be refused here. The caller still scans
                #     the whole string as text.
                if rule is not None:
                    raise RecordError(REASON_TOO_DEEP)
                self._redact_embedded_json(value, depth)
                pairs.append(pair)
                continue

            if rule is not None and rule.action == REMOVE:
                self._count(rule)
                changed = True
                continue
            if rule is not None:
                new_value = self._apply(rule, value)
            else:
                # The value may itself be JSON, a URL with a query, or text.
                new_value = self._redact_string(value, depth + 1)
            if new_value != value:
                # "surrogatepass": see sha256_digest. A lone surrogate in the
                # value must not make the encoding step raise.
                pair = raw_name + "=" + quote_plus(
                    new_value, safe=_FORM_SAFE_CHARACTERS, errors="surrogatepass"
                )
                changed = True
            # An untouched pair keeps its original spelling (`%20` versus `+`).
            pairs.append(pair)

        if not changed:
            return text
        return head + "&".join(pairs) + tail

    def _redact_text(self, text: str) -> str:
        """Apply the value rules to free text.

        1. Every rule searches the original text, so no rule ever sees another
           rule's replacement.
        2. Matches that overlap are merged into one range. Chains merge too:
           if A overlaps B and B overlaps C, all three become one range.
        3. One action is applied once to the whole text of each range: the
           strictest among the rules that matched in it (remove, then mask,
           hash, partial). Between rules with the same action, the one listed
           first in the rules file is chosen. The range is counted once, under
           that rule.

        Merging means text matched by any rule is never left readable just
        because a different rule won the overlap.
        """
        candidates = []
        for rule, priority in self._value_rules:
            candidates.extend(
                (start, end, priority, rule) for start, end in _find_matches(rule, text)
            )
        if not candidates:
            return text

        pieces = []
        cursor = 0
        for start, end, rule in _merge_overlapping(candidates):
            pieces.append(text[cursor:start])
            pieces.append(self._apply(rule, text[start:end]))
            cursor = end
        pieces.append(text[cursor:])
        return "".join(pieces)

    # --- helpers ------------------------------------------------------------

    def _apply(self, rule: KeyRule | ValueRule, value: str) -> str:
        """Return the replacement for `value`, counting it if it differs."""
        if not value:
            return value
        # A key rule fires again on every run and needs the tagged digest it
        # can recognise; a value rule gets the bare digest (see sha256_digest).
        replacement = apply_action(
            rule.action, value, self._settings, tagged_hash=isinstance(rule, KeyRule)
        )
        if replacement != value:
            self._count(rule)
        return replacement

    def _count(self, rule: KeyRule | ValueRule) -> None:
        self._record_counts[rule.name] += 1


def _split_form(text: str) -> tuple[str, str, str] | None:
    """Find the `name=value&name=value` pairs in `text`.

    Returns:
        (head, pairs, tail), which joined together give `text` again, or None
        if `text` does not look like a form at all:

            "a=1&b=2"               ->  ("", "a=1&b=2", "")
            "/reset?token=abc#top"  ->  ("/reset?", "token=abc", "#top")

    The test for "looks like a form" is deliberately loose: no whitespace and
    at least one `=`. A false positive costs nothing, because the caller
    still scans the whole string as text afterwards.
    """
    if "=" not in text or _WHITESPACE.search(text):
        return None
    # In "/reset?token=abc" the pairs start after the "?". If an "=" comes
    # first, as in "a=1&q=what?", the "?" belongs to a value and the whole
    # string is the list of pairs.
    question_mark = text.find("?")
    if question_mark == -1 or "=" in text[:question_mark]:
        return "", text, ""
    head = text[: question_mark + 1]
    query, hash_mark, fragment = text[question_mark + 1 :].partition("#")
    return head, query, hash_mark + fragment


def _find_matches(rule: ValueRule, text: str) -> list[tuple[int, int]]:
    """Return the (start, end) spans in `text` that `rule` matches and accepts.

    The spans of a rule without a validator never overlap each other: after a
    match the search resumes where it ended. With a validator they may, and
    _merge_overlapping joins them into one range.
    """
    spans = []
    position = 0
    while (match := rule.pattern.search(text, position)) is not None:
        start, end = match.span()
        if start == end:
            # A zero-width match (a lookahead, say) redacts nothing, and
            # searching again from the same place would loop forever.
            position = end + 1
        elif rule.validator is None or rule.validator(match.group()):
            spans.append((start, end))
            # A validator judges one candidate at a time, so a valid one can
            # start inside an accepted one: in "4111 1111 1111 1111 3129 3741
            # 1406" the last group of the first card also begins a card. Left
            # for the next run, it would be found there next to the four
            # digits `partial` keeps, and the output would not be idempotent.
            # A pattern without a validator sets its own boundaries; resuming
            # inside its match would only find pieces of the same text.
            position = start + 1 if rule.validator is not None else end
        else:
            # The validator refused this candidate. Resume one character
            # later, not after it: with a pattern that allows separators,
            # "2024 4111 1111 1111 1111" first yields the invalid candidate
            # "2024 4111 1111 1111", and the real card starts inside it.
            position = start + 1
    return spans


def _merge_overlapping(candidates: list[tuple]) -> list[tuple[int, int, ValueRule]]:
    """Merge overlapping matches and pick one rule for each merged range.

    Args:
        candidates: (start, end, priority, rule) for every accepted match, in
            any order. `priority` is (strictness of the action, position in
            the rules file); the lowest one wins.

    Returns:
        (start, end, rule) for each merged range, left to right. Ranges that
        only touch, where one ends exactly where the next begins, stay
        separate: no character belongs to both.
    """
    merged = []
    # Sorted by start, a match overlaps the current range exactly when it
    # starts before the range's end, however many matches were merged so far.
    for start, end, priority, rule in sorted(candidates, key=lambda candidate: candidate[0]):
        if merged and start < merged[-1][1]:
            range_start, range_end, best_priority, best_rule = merged[-1]
            if priority < best_priority:
                best_priority, best_rule = priority, rule
            merged[-1] = (range_start, max(range_end, end), best_priority, best_rule)
        else:
            merged.append((start, end, priority, rule))
    return [(start, end, rule) for start, end, _priority, rule in merged]

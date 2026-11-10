"""Loading, validating and compiling the redaction rules (rules.yaml).

The loader is deliberately strict ("fail closed"). A rules file that cannot be
understood completely is rejected as a whole, because a rule that is silently
ignored is a leak: a typo such as `actoin: mask` must stop the program, not
disable the rule. Callers load the rules before reading any traffic, so a bad
file means nothing is processed at all.

The result is an immutable RuleSet whose regular expressions are compiled once
and can be shared freely.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from redactor.actions import ACTIONS, VALIDATORS, ActionSettings

SCOPE_HEADERS = "headers"
SCOPE_BODY = "body"
SCOPE_ANY = "any"
SCOPES = frozenset({SCOPE_HEADERS, SCOPE_BODY, SCOPE_ANY})

SUPPORTED_VERSION = 1
SUPPORTED_HASH_ALGORITHM = "sha256"

# re.ASCII makes \b, \d and \w mean what they mean in Go's regexp package,
# which the provided rules were written for. With Python's Unicode default,
# \b sees no boundary between a letter of any script and a digit, so a card
# number glued to Japanese text would not be found.
_REGEX_FLAGS = re.ASCII


class RulesError(Exception):
    """The rules file is missing, unreadable or invalid."""


@dataclass(frozen=True)
class KeyRule:
    """A rule that selects values by the *name* of their JSON key or HTTP header.

    Attributes:
        name: Unique rule name, used in the redaction summary.
        scope: Where the rule applies: "headers", "body" or "any".
        action: What to do with the value (one of actions.ACTIONS).
        exact: Lower-cased names to match, when the rule uses `match.exact`.
        regex: Compiled pattern, when the rule uses `match.regex`.
    """

    name: str
    scope: str
    action: str
    exact: frozenset[str] = frozenset()
    regex: re.Pattern[str] | None = None

    def matches(self, key_name: str, scope: str) -> bool:
        """Tell whether this rule applies to `key_name` found in `scope`.

        Args:
            key_name: The JSON key, header name or form field name.
            scope: Where the key was found: SCOPE_HEADERS or SCOPE_BODY.
        """
        if self.scope != SCOPE_ANY and self.scope != scope:
            return False
        if self.regex is not None:
            # search(), not fullmatch(): the rule author controls anchoring.
            # The provided patterns are anchored with ^...$ on purpose, so
            # that `password` does not also match `password_hint`.
            return self.regex.search(key_name) is not None
        # Exact names are compared without regard to case. HTTP header names
        # are case-insensitive, and real traffic contains `authorization`
        # and `AUTHORIZATION`.
        return key_name.lower() in self.exact


@dataclass(frozen=True)
class ValueRule:
    """A rule that selects text by the *content* of a string value.

    Attributes:
        name: Unique rule name, used in the redaction summary.
        action: What to do with each match (one of actions.ACTIONS).
        pattern: Compiled pattern searched for inside string values.
        validator: Optional extra check; a match counts only if it returns True.
    """

    name: str
    action: str
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None


@dataclass(frozen=True)
class RuleSet:
    """All rules from one rules file, in file order."""

    settings: ActionSettings
    key_rules: tuple[KeyRule, ...]
    value_rules: tuple[ValueRule, ...]

    def find_key_rule(self, key_name: str, scope: str) -> KeyRule | None:
        """Return the first key rule matching `key_name` in `scope`, or None.

        File order decides between several matching rules: the first one wins,
        like firewall rules. That keeps the outcome predictable from reading
        the file top to bottom.
        """
        for rule in self.key_rules:
            if rule.matches(key_name, scope):
                return rule
        return None

    @property
    def rule_names(self) -> tuple[str, ...]:
        """Names of all rules in file order, key rules first."""
        return tuple(rule.name for rule in (*self.key_rules, *self.value_rules))


def load_rules(path: str | Path) -> RuleSet:
    """Read, validate and compile the rules file at `path`.

    Raises:
        RulesError: If the file cannot be read or is not a valid rules file.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RulesError(f"cannot read rules file {str(path)!r}: {exc}") from exc
    return parse_rules(text)


def parse_rules(text: str) -> RuleSet:
    """Validate and compile rules given as YAML text.

    Raises:
        RulesError: If the text is not valid YAML or not a valid rules file.
    """
    try:
        # safe_load builds only plain data (dict, list, str, int, ...).
        # yaml.load can construct arbitrary Python objects from the file.
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RulesError(f"rules file is not valid YAML: {exc}") from exc

    root = _mapping(document, "rules file")
    _check_keys(
        root,
        allowed={"version", "settings", "key_rules", "value_rules"},
        required={"version"},
        where="rules file",
    )
    # type() rather than ==: in Python True == 1, and YAML reads `yes` as True.
    if type(root["version"]) is not int or root["version"] != SUPPORTED_VERSION:
        raise RulesError(
            f"version: expected {SUPPORTED_VERSION}, got {root['version']!r}"
        )

    settings = _parse_settings(root.get("settings"))
    key_rules = tuple(
        _parse_key_rule(raw, f"key_rules[{index}]")
        for index, raw in enumerate(_list(root.get("key_rules"), "key_rules"))
    )
    value_rules = tuple(
        _parse_value_rule(raw, f"value_rules[{index}]")
        for index, raw in enumerate(_list(root.get("value_rules"), "value_rules"))
    )

    # A file without rules would pass every record through untouched.
    if not key_rules and not value_rules:
        raise RulesError("rules file defines no rules")

    # The summary reports counts per rule name, so names must not collide.
    seen: set[str] = set()
    for rule in (*key_rules, *value_rules):
        if rule.name in seen:
            raise RulesError(f"duplicate rule name: {rule.name!r}")
        seen.add(rule.name)

    return RuleSet(settings=settings, key_rules=key_rules, value_rules=value_rules)


def _parse_settings(raw: object) -> ActionSettings:
    """Build ActionSettings from the optional `settings:` block."""
    defaults = ActionSettings()
    if raw is None:
        return defaults

    settings = _mapping(raw, "settings")
    _check_keys(settings, allowed={"mask", "partial", "hash"}, where="settings")
    mask = _section(settings, "mask", allowed={"replacement"})
    partial = _section(settings, "partial", allowed={"keep_last", "fill"})
    hash_ = _section(settings, "hash", allowed={"algorithm"})

    replacement = mask.get("replacement", defaults.mask_replacement)
    if not isinstance(replacement, str) or not replacement:
        raise RulesError("settings.mask.replacement: expected a non-empty string")

    keep_last = partial.get("keep_last", defaults.keep_last)
    # type() rather than isinstance(): bool is a subclass of int.
    if type(keep_last) is not int or keep_last < 0:
        raise RulesError("settings.partial.keep_last: expected an integer >= 0")

    fill = partial.get("fill", defaults.fill)
    # Exactly one character keeps the masked text as long as the original,
    # which is what makes `partial` idempotent.
    if not isinstance(fill, str) or len(fill) != 1:
        raise RulesError("settings.partial.fill: expected exactly one character")

    algorithm = hash_.get("algorithm", SUPPORTED_HASH_ALGORITHM)
    if algorithm != SUPPORTED_HASH_ALGORITHM:
        raise RulesError(
            f"settings.hash.algorithm: only {SUPPORTED_HASH_ALGORITHM!r} is supported, "
            f"got {algorithm!r}"
        )

    return ActionSettings(mask_replacement=replacement, keep_last=keep_last, fill=fill)


def _parse_key_rule(raw: object, where: str) -> KeyRule:
    """Validate one entry of `key_rules` and compile its matcher."""
    rule = _mapping(raw, where)
    fields = {"name", "scope", "match", "action"}
    _check_keys(rule, allowed=fields, required=fields, where=where)

    name = _string(rule["name"], f"{where}.name")
    where = f"{where} ({name!r})"
    scope = _choice(rule["scope"], SCOPES, f"{where}.scope")
    action = _choice(rule["action"], ACTIONS, f"{where}.action")

    match = _mapping(rule["match"], f"{where}.match")
    _check_keys(match, allowed={"exact", "regex"}, where=f"{where}.match")
    if len(match) != 1:
        raise RulesError(f"{where}.match: expected exactly one of 'exact' or 'regex'")

    if "exact" in match:
        names = match["exact"]
        if not isinstance(names, list) or not names:
            raise RulesError(f"{where}.match.exact: expected a non-empty list of names")
        exact = frozenset(
            _string(item, f"{where}.match.exact[{index}]").lower()
            for index, item in enumerate(names)
        )
        return KeyRule(name=name, scope=scope, action=action, exact=exact)

    regex = _compile(match["regex"], f"{where}.match.regex")
    return KeyRule(name=name, scope=scope, action=action, regex=regex)


def _parse_value_rule(raw: object, where: str) -> ValueRule:
    """Validate one entry of `value_rules` and compile its pattern."""
    rule = _mapping(raw, where)
    _check_keys(
        rule,
        allowed={"name", "pattern", "validator", "action"},
        required={"name", "pattern", "action"},
        where=where,
    )

    name = _string(rule["name"], f"{where}.name")
    where = f"{where} ({name!r})"
    action = _choice(rule["action"], ACTIONS, f"{where}.action")

    pattern = _compile(rule["pattern"], f"{where}.pattern")
    # A pattern such as `\d*` matches the empty string at every position. It
    # would "find" something in every value without ever matching real text.
    if pattern.search("") is not None:
        raise RulesError(f"{where}.pattern: must not match the empty string")

    validator = None
    if "validator" in rule:
        validator = VALIDATORS[_choice(rule["validator"], VALIDATORS, f"{where}.validator")]

    return ValueRule(name=name, action=action, pattern=pattern, validator=validator)


# --- small validation helpers -------------------------------------------------
# Each one raises RulesError with the location of the problem (`where`), so the
# person editing rules.yaml can find it. Rule files contain patterns and names,
# never traffic, so echoing their content in an error message is safe.


def _mapping(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        raise RulesError(f"{where}: expected a mapping, got {type(value).__name__}")
    return value


def _list(value: object, where: str) -> list:
    """Return `value` as a list. A missing section (None) is an empty list."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise RulesError(f"{where}: expected a list, got {type(value).__name__}")
    return value


def _section(parent: dict, name: str, allowed: set[str]) -> dict:
    """Return the optional sub-mapping `parent[name]` after checking its keys."""
    where = f"settings.{name}"
    section = _mapping(parent.get(name, {}), where)
    _check_keys(section, allowed=allowed, where=where)
    return section


def _check_keys(
    mapping: dict, allowed: set[str], where: str, required: set[str] = frozenset()
) -> None:
    """Reject unknown fields and report missing required ones."""
    for key in mapping:
        if key not in allowed:
            raise RulesError(
                f"{where}: unknown field {key!r} (allowed: {', '.join(sorted(allowed))})"
            )
    for key in sorted(required):
        if key not in mapping:
            raise RulesError(f"{where}: missing required field {key!r}")


def _string(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise RulesError(f"{where}: expected a non-empty string, got {value!r}")
    return value


def _choice(value: object, allowed, where: str) -> str:
    """Return `value` if it is one of the `allowed` strings."""
    # The isinstance check comes first: YAML can hand us a list here, and
    # testing an unhashable list for membership in a set raises TypeError.
    if not isinstance(value, str) or value not in allowed:
        raise RulesError(
            f"{where}: expected one of {', '.join(sorted(allowed))}; got {value!r}"
        )
    return value


def _compile(pattern: object, where: str) -> re.Pattern[str]:
    text = _string(pattern, where)
    try:
        return re.compile(text, _REGEX_FLAGS)
    except re.error as exc:
        raise RulesError(f"{where}: invalid regular expression: {exc}") from exc

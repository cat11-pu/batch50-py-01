"""GraphQL abuse guard: depth and cost budgets, persisted allowlist, per-client quota."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import threading
import time
from dataclasses import dataclass
from typing import Any


class GraphqlGuardError(ValueError):
    """Raised when a GraphQL request or quota operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Admission:
    fingerprint: str
    depth: int
    cost: int
    client: str
    remaining: int


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    position: int


@dataclass(frozen=True)
class _Argument:
    name: str
    value: "_Value"


@dataclass(frozen=True)
class _Directive:
    name: str
    arguments: tuple[_Argument, ...] = ()


@dataclass(frozen=True)
class _Value:
    kind: str
    value: Any


@dataclass(frozen=True)
class _Field:
    name: str
    alias: str | None
    arguments: tuple[_Argument, ...]
    directives: tuple[_Directive, ...]
    selection: "_SelectionSet | None"


@dataclass(frozen=True)
class _FragmentSpread:
    name: str
    directives: tuple[_Directive, ...]


@dataclass(frozen=True)
class _InlineFragment:
    type_condition: str | None
    directives: tuple[_Directive, ...]
    selection: "_SelectionSet"


@dataclass(frozen=True)
class _SelectionSet:
    selections: tuple[_Field | _FragmentSpread | _InlineFragment, ...]


@dataclass(frozen=True)
class _VariableDefinition:
    name: str
    type_ref: str
    default: _Value | None
    directives: tuple[_Directive, ...]


@dataclass(frozen=True)
class _Operation:
    kind: str
    name: str | None
    variables: tuple[_VariableDefinition, ...]
    directives: tuple[_Directive, ...]
    selection: _SelectionSet


@dataclass(frozen=True)
class _Fragment:
    name: str
    type_condition: str | None
    directives: tuple[_Directive, ...]
    selection: _SelectionSet


@dataclass(frozen=True)
class _Document:
    operations: tuple[_Operation, ...]
    fragments: dict[str, _Fragment]


@dataclass
class _ClientState:
    tokens: float
    last_refill: float
    concurrent: int = 0


@dataclass(frozen=True)
class _Analysis:
    cost: int
    depth: int
    introspection: bool


class _ParseError(ValueError):
    pass


_NAME_RE = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_NUMBER_RE = re.compile(
    r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
)
_PUNCTUATION = frozenset("!$&():=@[]{|}")
_IGNORABLE = frozenset(" \t\r\n,\ufeff")
_INTROSPECTION_FIELDS = frozenset({"__schema", "__type", "__typename"})
_DEFAULT_LIST_ARGUMENTS = frozenset(
    {
        "after",
        "before",
        "count",
        "first",
        "ids",
        "items",
        "last",
        "limit",
        "offset",
        "page",
        "page_size",
        "per_page",
        "size",
        "skip",
        "take",
        "values",
    }
)
_POLICY_ALIASES = {
    "default_field_weight": "field_weight",
    "default_weight": "field_weight",
    "fragment_expansion_limit": "max_fragment_expansions",
    "introspection": "allow_introspection",
    "list_cost_multiplier": "list_multiplier",
    "max_expansions": "max_fragment_expansions",
    "token_refill_rate": "refill_rate",
    "weights": "field_weights",
}
_MAX_PARSE_DEPTH = 600


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    index = 0
    length = len(text)

    while index < length:
        char = text[index]
        if char in _IGNORABLE:
            index += 1
            continue
        if char == "#":
            newline = text.find("\n", index)
            index = length if newline < 0 else newline + 1
            continue

        position = index
        if text.startswith("...", index):
            tokens.append(_Token("SPREAD", "...", position))
            index += 3
            continue

        if char == '"':
            if text.startswith('"""', index):
                index += 3
                parts: list[str] = []
                while index < length:
                    if text.startswith('\\"""', index):
                        parts.append('"""')
                        index += 4
                    elif text.startswith('"""', index):
                        index += 3
                        break
                    else:
                        parts.append(text[index])
                        index += 1
                else:
                    raise _ParseError(
                        f"unterminated block string at position {position}"
                    )
                tokens.append(_Token("STRING", "".join(parts), position))
                continue

            index += 1
            raw: list[str] = []
            while index < length:
                char = text[index]
                if char == '"':
                    index += 1
                    break
                if char in "\r\n":
                    raise _ParseError(
                        f"newline in string at position {position}"
                    )
                if char == "\\":
                    if index + 1 >= length:
                        raise _ParseError(
                            f"unterminated string at position {position}"
                        )
                    raw.append(text[index : index + 2])
                    index += 2
                    continue
                raw.append(char)
                index += 1
            else:
                raise _ParseError(f"unterminated string at position {position}")
            try:
                decoded = json.loads('"' + "".join(raw) + '"')
            except (TypeError, ValueError) as exc:
                raise _ParseError(
                    f"invalid string escape at position {position}"
                ) from exc
            tokens.append(_Token("STRING", decoded, position))
            continue

        number = _NUMBER_RE.match(text, index)
        if number is not None:
            value = number.group(0)
            index = number.end()
            kind = "float" if "." in value or "e" in value.lower() else "int"
            tokens.append(_Token(kind, value, position))
            continue

        name = _NAME_RE.match(text, index)
        if name is not None:
            value = name.group(0)
            tokens.append(_Token("NAME", value, position))
            index = name.end()
            continue

        if char in _PUNCTUATION:
            tokens.append(_Token(char, char, position))
            index += 1
            continue

        raise _ParseError(f"unexpected character {char!r} at position {position}")

    tokens.append(_Token("EOF", "", length))
    return tokens


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self._tokens = tokens
        self._index = 0
        self._depth = 0

    def _peek(self, offset: int = 0) -> _Token:
        position = min(self._index + offset, len(self._tokens) - 1)
        return self._tokens[position]

    def _advance(self) -> _Token:
        token = self._peek()
        self._index += 1
        return token

    def _accept(self, kind: str, value: str | None = None) -> _Token | None:
        token = self._peek()
        if token.kind != kind or (value is not None and token.value != value):
            return None
        return self._advance()

    def _expect(self, kind: str, value: str | None = None) -> _Token:
        token = self._peek()
        if token.kind != kind or (value is not None and token.value != value):
            expected = value if value is not None else kind
            found = token.value or token.kind
            raise _ParseError(
                f"expected {expected!r}, found {found!r} "
                f"at position {token.position}"
            )
        return self._advance()

    def _enter(self) -> None:
        self._depth += 1
        if self._depth > _MAX_PARSE_DEPTH:
            raise _ParseError(
                f"query nesting exceeds parser limit {_MAX_PARSE_DEPTH}"
            )

    def _leave(self) -> None:
        self._depth -= 1

    def parse_document(self) -> _Document:
        operations: list[_Operation] = []
        fragments: dict[str, _Fragment] = {}

        while self._peek().kind != "EOF":
            token = self._peek()
            if token.kind == "{":
                operations.append(
                    _Operation(
                        kind="query",
                        name=None,
                        variables=(),
                        directives=(),
                        selection=self._parse_selection_set(),
                    )
                )
            elif token.kind == "NAME" and token.value in {
                "query",
                "mutation",
                "subscription",
            }:
                operations.append(self._parse_operation())
            elif token.kind == "NAME" and token.value == "fragment":
                fragment = self._parse_fragment()
                if fragment.name in fragments:
                    raise _ParseError(
                        f"duplicate fragment {fragment.name!r} "
                        f"at position {token.position}"
                    )
                fragments[fragment.name] = fragment
            else:
                raise _ParseError(
                    f"expected an operation or fragment at position "
                    f"{token.position}"
                )

        if not operations:
            raise _ParseError("document contains no executable operation")
        return _Document(tuple(operations), fragments)

    def _parse_operation(self) -> _Operation:
        kind = self._expect("NAME").value
        name = None
        if self._peek().kind == "NAME":
            name = self._advance().value

        variables: tuple[_VariableDefinition, ...] = ()
        if self._peek().kind == "(":
            variables = self._parse_variable_definitions()
        directives = self._parse_directives()
        selection = self._parse_selection_set()
        return _Operation(kind, name, variables, directives, selection)

    def _parse_variable_definitions(self) -> tuple[_VariableDefinition, ...]:
        self._expect("(")
        definitions: list[_VariableDefinition] = []
        while self._peek().kind != ")":
            if self._peek().kind == "EOF":
                raise _ParseError("unterminated variable definitions")
            self._expect("$")
            name = self._expect("NAME").value
            self._expect(":")
            type_ref = self._parse_type_reference()
            default = None
            if self._accept("=") is not None:
                default = self._parse_value()
            directives = self._parse_directives()
            definitions.append(
                _VariableDefinition(name, type_ref, default, directives)
            )
        self._expect(")")
        return tuple(definitions)

    def _parse_type_reference(self) -> str:
        if self._accept("[") is not None:
            inner = self._parse_type_reference()
            self._expect("]")
            result = f"[{inner}]"
        else:
            result = self._expect("NAME").value
        if self._accept("!") is not None:
            result += "!"
        return result

    def _parse_fragment(self) -> _Fragment:
        self._expect("NAME", "fragment")
        name = self._expect("NAME").value
        self._expect("NAME", "on")
        type_condition = self._expect("NAME").value
        directives = self._parse_directives()
        selection = self._parse_selection_set()
        return _Fragment(name, type_condition, directives, selection)

    def _parse_selection_set(self) -> _SelectionSet:
        self._enter()
        try:
            self._expect("{")
            selections: list[_Field | _FragmentSpread | _InlineFragment] = []
            while self._peek().kind != "}":
                if self._peek().kind == "EOF":
                    raise _ParseError("unterminated selection set")
                selections.append(self._parse_selection())
            self._expect("}")
            if not selections:
                raise _ParseError("empty selection set")
            return _SelectionSet(tuple(selections))
        finally:
            self._leave()

    def _parse_selection(self) -> _Field | _FragmentSpread | _InlineFragment:
        if self._accept("SPREAD") is not None:
            if self._peek().kind == "NAME" and self._peek().value == "on":
                self._advance()
                type_condition = self._expect("NAME").value
                directives = self._parse_directives()
                selection = self._parse_selection_set()
                return _InlineFragment(type_condition, directives, selection)
            if self._peek().kind in {"{", "@"}:
                directives = self._parse_directives()
                selection = self._parse_selection_set()
                return _InlineFragment(None, directives, selection)
            name = self._expect("NAME").value
            directives = self._parse_directives()
            return _FragmentSpread(name, directives)

        first_name = self._expect("NAME").value
        alias = None
        name = first_name
        if self._accept(":") is not None:
            alias = first_name
            name = self._expect("NAME").value

        arguments: tuple[_Argument, ...] = ()
        if self._peek().kind == "(":
            arguments = self._parse_arguments()
        directives = self._parse_directives()
        selection = None
        if self._peek().kind == "{":
            selection = self._parse_selection_set()
        return _Field(name, alias, arguments, directives, selection)

    def _parse_arguments(self) -> tuple[_Argument, ...]:
        self._expect("(")
        arguments: list[_Argument] = []
        while self._peek().kind != ")":
            if self._peek().kind == "EOF":
                raise _ParseError("unterminated argument list")
            name = self._expect("NAME").value
            self._expect(":")
            arguments.append(_Argument(name, self._parse_value()))
        self._expect(")")
        return tuple(arguments)

    def _parse_directives(self) -> tuple[_Directive, ...]:
        directives: list[_Directive] = []
        while self._accept("@") is not None:
            name = self._expect("NAME").value
            arguments: tuple[_Argument, ...] = ()
            if self._peek().kind == "(":
                arguments = self._parse_arguments()
            directives.append(_Directive(name, arguments))
        return tuple(directives)

    def _parse_value(self) -> _Value:
        self._enter()
        try:
            token = self._peek()
            if token.kind == "$":
                self._advance()
                return _Value("variable", self._expect("NAME").value)
            if token.kind == "STRING":
                self._advance()
                return _Value("string", token.value)
            if token.kind in {"int", "float"}:
                self._advance()
                return _Value(token.kind, token.value)
            if token.kind == "NAME":
                self._advance()
                if token.value == "true":
                    return _Value("boolean", True)
                if token.value == "false":
                    return _Value("boolean", False)
                if token.value == "null":
                    return _Value("null", None)
                return _Value("enum", token.value)
            if token.kind == "[":
                self._advance()
                values: list[_Value] = []
                while self._peek().kind != "]":
                    if self._peek().kind == "EOF":
                        raise _ParseError("unterminated list value")
                    values.append(self._parse_value())
                self._expect("]")
                return _Value("list", tuple(values))
            if token.kind == "{":
                self._advance()
                fields: list[tuple[str, _Value]] = []
                while self._peek().kind != "}":
                    if self._peek().kind == "EOF":
                        raise _ParseError("unterminated object value")
                    name = self._expect("NAME").value
                    self._expect(":")
                    fields.append((name, self._parse_value()))
                self._expect("}")
                return _Value("object", tuple(fields))
            raise _ParseError(f"expected a value at position {token.position}")
        finally:
            self._leave()


def _parse(query: str) -> _Document:
    if not isinstance(query, str):
        raise GraphqlGuardError(
            "INVALID_QUERY", {"reason": "query must be a string"}
        )
    try:
        return _Parser(_tokenize(query)).parse_document()
    except _ParseError as exc:
        raise GraphqlGuardError("INVALID_QUERY", {"reason": str(exc)}) from exc
    except RecursionError as exc:
        raise GraphqlGuardError(
            "INVALID_QUERY",
            {"reason": "query nesting is too deep to analyze"},
        ) from exc


def _canonical_value(value: _Value) -> str:
    if value.kind == "string":
        return "string:" + json.dumps(
            value.value, ensure_ascii=False, separators=(",", ":")
        )
    if value.kind == "variable":
        return "variable:$" + value.value
    if value.kind == "boolean":
        return "boolean:" + ("true" if value.value else "false")
    if value.kind == "null":
        return "null"
    if value.kind == "list":
        return (
            "list:["
            + ",".join(_canonical_value(item) for item in value.value)
            + "]"
        )
    if value.kind == "object":
        fields = sorted(
            (name, _canonical_value(field_value))
            for name, field_value in value.value
        )
        return (
            "object:{"
            + ",".join(name + ":" + field_value for name, field_value in fields)
            + "}"
        )
    return value.kind + ":" + str(value.value)


def _canonical_arguments(arguments: tuple[_Argument, ...]) -> str:
    if not arguments:
        return ""
    rendered = sorted(
        argument.name + ":" + _canonical_value(argument.value)
        for argument in arguments
    )
    return "(" + ",".join(rendered) + ")"


def _canonical_directives(directives: tuple[_Directive, ...]) -> str:
    if not directives:
        return ""
    rendered = sorted(
        "@" + directive.name + _canonical_arguments(directive.arguments)
        for directive in directives
    )
    return "".join(rendered)


def _canonical_selection_set(selection: _SelectionSet) -> str:
    rendered: list[str] = []
    for item in selection.selections:
        if isinstance(item, _Field):
            alias = (item.alias + ":") if item.alias is not None else ""
            child = (
                "{" + _canonical_selection_set(item.selection) + "}"
                if item.selection is not None
                else ""
            )
            rendered.append(
                "field:"
                + alias
                + item.name
                + _canonical_arguments(item.arguments)
                + _canonical_directives(item.directives)
                + child
            )
        elif isinstance(item, _FragmentSpread):
            rendered.append(
                "spread:" + item.name + _canonical_directives(item.directives)
            )
        else:
            condition = (
                "on:" + item.type_condition
                if item.type_condition is not None
                else ""
            )
            rendered.append(
                "inline:"
                + condition
                + _canonical_directives(item.directives)
                + "{"
                + _canonical_selection_set(item.selection)
                + "}"
            )
    rendered.sort()
    return ",".join(rendered)


def _canonical_fingerprint(document: _Document) -> str:
    rendered_operations: list[str] = []
    for operation in document.operations:
        variables = sorted(
            "$"
            + variable.name
            + ":"
            + variable.type_ref
            + (
                "=" + _canonical_value(variable.default)
                if variable.default is not None
                else ""
            )
            + _canonical_directives(variable.directives)
            for variable in operation.variables
        )
        rendered_operations.append(
            "operation:"
            + operation.kind
            + ":"
            + (operation.name or "")
            + ":("
            + ",".join(variables)
            + "):"
            + _canonical_directives(operation.directives)
            + "{"
            + _canonical_selection_set(operation.selection)
            + "}"
        )

    rendered_fragments: list[str] = []
    for name in sorted(document.fragments):
        fragment = document.fragments[name]
        rendered_fragments.append(
            "fragment:"
            + name
            + ":on:"
            + (fragment.type_condition or "")
            + ":"
            + _canonical_directives(fragment.directives)
            + "{"
            + _canonical_selection_set(fragment.selection)
            + "}"
        )

    canonical = (
        "operations=[" + "|".join(sorted(rendered_operations)) + "]"
        "fragments=[" + "|".join(rendered_fragments) + "]"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _selection_spreads(selection: _SelectionSet) -> list[str]:
    result: list[str] = []
    for item in selection.selections:
        if isinstance(item, _FragmentSpread):
            result.append(item.name)
        elif isinstance(item, _InlineFragment):
            result.extend(_selection_spreads(item.selection))
        elif item.selection is not None:
            result.extend(_selection_spreads(item.selection))
    return result


def _validate_fragments(document: _Document) -> None:
    references: dict[str, list[str]] = {
        name: _selection_spreads(fragment.selection)
        for name, fragment in document.fragments.items()
    }

    for operation in document.operations:
        for name in _selection_spreads(operation.selection):
            if name not in document.fragments:
                raise GraphqlGuardError(
                    "INVALID_QUERY",
                    {"reason": f"unknown fragment {name!r}"},
                )

    for name, spread_names in references.items():
        for spread_name in spread_names:
            if spread_name not in document.fragments:
                raise GraphqlGuardError(
                    "INVALID_QUERY",
                    {
                        "reason": (
                            f"fragment {name!r} references unknown fragment "
                            f"{spread_name!r}"
                        )
                    },
                )

    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(name: str) -> None:
        current = state.get(name, 0)
        if current == 2:
            return
        if current == 1:
            cycle_start = stack.index(name)
            cycle = stack[cycle_start:] + [name]
            raise GraphqlGuardError(
                "CYCLE_DETECTED",
                {
                    "reason": "fragment cycle detected",
                    "cycle": cycle,
                },
            )

        state[name] = 1
        stack.append(name)
        for spread_name in references[name]:
            visit(spread_name)
        stack.pop()
        state[name] = 2

    for fragment_name in sorted(references):
        visit(fragment_name)


class _Estimator:
    def __init__(
        self,
        *,
        document: _Document,
        field_weight: int,
        field_weights: dict[str, int],
        list_multiplier: int,
        list_argument_names: frozenset[str],
        max_expansions: int,
    ) -> None:
        self._document = document
        self._field_weight = field_weight
        self._field_weights = field_weights
        self._list_multiplier = list_multiplier
        self._list_argument_names = list_argument_names
        self._max_expansions = max_expansions
        self._expansions = 0

    def run(self) -> _Analysis:
        total_cost = 0
        max_depth = 0
        introspection = False
        for operation in self._document.operations:
            cost, depth, found = self._estimate_selection(operation.selection)
            total_cost += cost
            max_depth = max(max_depth, depth)
            introspection = introspection or found
        return _Analysis(total_cost, max_depth, introspection)

    def _is_list_field(self, field_node: _Field) -> bool:
        for argument in field_node.arguments:
            if argument.value.kind == "list":
                return True
            if argument.name.casefold() in self._list_argument_names:
                return True
        return False

    def _estimate_selection(
        self, selection: _SelectionSet
    ) -> tuple[int, int, bool]:
        total_cost = 0
        max_depth = 0
        introspection = False

        for item in selection.selections:
            if isinstance(item, _Field):
                child_cost = 0
                child_depth = 0
                child_introspection = False
                if item.selection is not None:
                    child_cost, child_depth, child_introspection = (
                        self._estimate_selection(item.selection)
                    )

                multiplier = (
                    self._list_multiplier if self._is_list_field(item) else 1
                )
                weight = self._field_weights.get(
                    item.name, self._field_weight
                )
                total_cost += weight * (1 + multiplier * child_cost)
                if item.selection is None:
                    depth = 1
                else:
                    depth = 1 + child_depth
                max_depth = max(max_depth, depth)
                introspection = introspection or child_introspection
                if item.name in _INTROSPECTION_FIELDS:
                    introspection = True
                continue

            if isinstance(item, _FragmentSpread):
                self._expansions += 1
                if self._expansions > self._max_expansions:
                    raise GraphqlGuardError(
                        "FRAGMENT_EXPANSION_EXCEEDED",
                        {
                            "actual": self._expansions,
                            "limit": self._max_expansions,
                            "reason": "fragment expansion limit exceeded",
                        },
                    )
                fragment = self._document.fragments[item.name]
                cost, depth, found = self._estimate_selection(
                    fragment.selection
                )
                total_cost += cost
                max_depth = max(max_depth, depth)
                introspection = introspection or found
                continue

            cost, depth, found = self._estimate_selection(item.selection)
            total_cost += cost
            max_depth = max(max_depth, depth)
            introspection = introspection or found

        return total_cost, max_depth, introspection


class GraphqlAbuseGuard:
    """Admit GraphQL operations against cost, depth, whitelist and quota rules."""

    def __init__(
        self,
        *,
        cost_budget: int = 1000,
        depth_limit: int = 12,
        burst: int = 10,
        max_concurrent: int = 4,
        strict_persisted: bool = True,
        cost_per_token: int = 100,
        field_weight: int = 1,
        list_multiplier: int = 10,
        max_fragment_expansions: int = 1000,
        allow_introspection: bool = False,
    ) -> None:
        if not _is_int(cost_budget) or cost_budget < 0:
            raise ValueError("cost_budget must be a non-negative integer")
        if not _is_int(depth_limit) or depth_limit < 0:
            raise ValueError("depth_limit must be a non-negative integer")
        if not _is_int(burst) or burst < 0:
            raise ValueError("burst must be a non-negative integer")
        if not _is_int(max_concurrent) or max_concurrent < 0:
            raise ValueError("max_concurrent must be a non-negative integer")
        if not isinstance(strict_persisted, bool):
            raise ValueError("strict_persisted must be a boolean")
        if not _is_int(cost_per_token) or cost_per_token < 1:
            raise ValueError("cost_per_token must be a positive integer")
        if not _is_int(field_weight) or field_weight < 1:
            raise ValueError("field_weight must be a positive integer")
        if not _is_int(list_multiplier) or list_multiplier < 1:
            raise ValueError("list_multiplier must be a positive integer")
        if not _is_int(max_fragment_expansions) or max_fragment_expansions < 1:
            raise ValueError(
                "max_fragment_expansions must be a positive integer"
            )
        if not isinstance(allow_introspection, bool):
            raise ValueError("allow_introspection must be a boolean")

        self.cost_budget = cost_budget
        self.depth_limit = depth_limit
        self.burst = burst
        self.max_concurrent = max_concurrent
        self.strict_persisted = strict_persisted
        self.cost_per_token = cost_per_token
        self._policy: dict[str, Any] = {
            "allow_introspection": allow_introspection,
            "field_weight": field_weight,
            "field_weights": {},
            "list_multiplier": list_multiplier,
            "max_fragment_expansions": max_fragment_expansions,
            "list_argument_names": tuple(sorted(_DEFAULT_LIST_ARGUMENTS)),
            "refill_rate": 0.0,
        }
        self._persisted: set[str] = set()
        self._clients: dict[str, _ClientState] = {}
        self._stats: dict[str, int] = {"admitted": 0, "tokens_spent": 0}
        self._lock = threading.RLock()

    @property
    def field_weight(self) -> int:
        with self._lock:
            return int(self._policy["field_weight"])

    @property
    def list_multiplier(self) -> int:
        with self._lock:
            return int(self._policy["list_multiplier"])

    @property
    def max_fragment_expansions(self) -> int:
        with self._lock:
            return int(self._policy["max_fragment_expansions"])

    @property
    def allow_introspection(self) -> bool:
        with self._lock:
            return bool(self._policy["allow_introspection"])

    def _parse_locked(self, query: str) -> tuple[_Document, str]:
        document = _parse(query)
        return document, _canonical_fingerprint(document)

    def register_persisted(
        self,
        query: str | None = None,
        *,
        fingerprint: str | None = None,
    ) -> str:
        with self._lock:
            computed = None
            if query is not None:
                _, computed = self._parse_locked(query)

            if fingerprint is not None:
                if not isinstance(fingerprint, str) or not fingerprint:
                    raise GraphqlGuardError(
                        "INVALID_FINGERPRINT",
                        {"reason": "fingerprint must be a non-empty string"},
                    )
                if computed is not None and fingerprint != computed:
                    raise GraphqlGuardError(
                        "FINGERPRINT_MISMATCH",
                        {
                            "reason": (
                                "registered fingerprint does not match the "
                                "canonical query fingerprint"
                            ),
                            "supplied": fingerprint,
                            "computed": computed,
                        },
                    )
                effective = fingerprint
            elif computed is not None:
                effective = computed
            else:
                raise GraphqlGuardError(
                    "INVALID_FINGERPRINT",
                    {"reason": "query or fingerprint is required"},
                )

            self._persisted.add(effective)
            return effective

    def revoke(self, fingerprint: str) -> bool:
        with self._lock:
            if fingerprint in self._persisted:
                self._persisted.remove(fingerprint)
                return True
            return False

    def persisted(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._persisted))

    def fingerprint(self, query: str) -> str:
        with self._lock:
            _, fingerprint = self._parse_locked(query)
            return fingerprint

    def _now(self, now: float | int | None) -> float:
        if now is None:
            return time.monotonic()
        if not _is_number(now):
            raise GraphqlGuardError(
                "INVALID_TIME", {"reason": "now must be a finite number"}
            )
        return float(now)

    def _client_locked(self, client: str, now: float) -> _ClientState:
        if not isinstance(client, str):
            raise GraphqlGuardError(
                "INVALID_CLIENT", {"reason": "client must be a string"}
            )
        state = self._clients.get(client)
        if state is None:
            state = _ClientState(float(self.burst), now, 0)
            self._clients[client] = state
        else:
            self._refill_locked(state, now)
        return state

    def _refill_locked(self, state: _ClientState, now: float) -> None:
        if now <= state.last_refill:
            return
        rate = float(self._policy["refill_rate"])
        if rate > 0:
            state.tokens = min(
                float(self.burst),
                state.tokens + (now - state.last_refill) * rate,
            )
        state.last_refill = now

    def _tokens_for_cost(self, cost: int) -> int:
        if cost <= 0:
            return 0
        return max(1, math.ceil(cost / self.cost_per_token))

    def _remaining(self, state: _ClientState) -> int:
        return max(0, int(math.floor(state.tokens + 1e-9)))

    def _analysis_locked(self, document: _Document) -> _Analysis:
        try:
            _validate_fragments(document)
            estimator = _Estimator(
                document=document,
                field_weight=int(self._policy["field_weight"]),
                field_weights=dict(self._policy["field_weights"]),
                list_multiplier=int(self._policy["list_multiplier"]),
                list_argument_names=frozenset(
                    self._policy["list_argument_names"]
                ),
                max_expansions=int(self._policy["max_fragment_expansions"]),
            )
            return estimator.run()
        except RecursionError as exc:
            raise GraphqlGuardError(
                "FRAGMENT_EXPANSION_EXCEEDED",
                {
                    "reason": (
                        "fragment expansion is too deep to estimate safely"
                    ),
                    "limit": self._policy["max_fragment_expansions"],
                },
            ) from exc

    def _check_analysis_locked(self, analysis: _Analysis) -> None:
        if analysis.introspection and not self._policy["allow_introspection"]:
            raise GraphqlGuardError(
                "INTROSPECTION_DENIED",
                {
                    "reason": "introspection is disabled",
                    "allow_introspection": False,
                },
            )
        if analysis.depth > self.depth_limit:
            raise GraphqlGuardError(
                "DEPTH_EXCEEDED",
                {
                    "reason": "query depth exceeds the configured limit",
                    "actual": analysis.depth,
                    "limit": self.depth_limit,
                    "depth": analysis.depth,
                    "depth_limit": self.depth_limit,
                },
            )
        if analysis.cost > self.cost_budget:
            raise GraphqlGuardError(
                "COST_EXCEEDED",
                {
                    "reason": "query cost exceeds the configured budget",
                    "actual": analysis.cost,
                    "limit": self.cost_budget,
                    "cost": analysis.cost,
                    "cost_budget": self.cost_budget,
                },
            )

    def admit(
        self,
        query: str,
        *,
        client: str = "default",
        now: float | None = None,
    ) -> Admission:
        with self._lock:
            timestamp = self._now(now)
            document, fingerprint = self._parse_locked(query)

            if self.strict_persisted and fingerprint not in self._persisted:
                raise GraphqlGuardError(
                    "PERSISTED_REQUIRED",
                    {
                        "reason": (
                            "strict persisted-query mode requires an exactly "
                            "registered fingerprint"
                        ),
                        "fingerprint": fingerprint,
                        "client": client,
                    },
                )

            analysis = self._analysis_locked(document)
            self._check_analysis_locked(analysis)

            state = self._client_locked(client, timestamp)
            if state.concurrent >= self.max_concurrent:
                raise GraphqlGuardError(
                    "CONCURRENCY_LIMITED",
                    {
                        "reason": "client concurrency limit reached",
                        "client": client,
                        "active": state.concurrent,
                        "limit": self.max_concurrent,
                    },
                )

            tokens_needed = self._tokens_for_cost(analysis.cost)
            if state.tokens + 1e-9 < tokens_needed:
                raise GraphqlGuardError(
                    "RATE_LIMITED",
                    {
                        "reason": "client token bucket is exhausted",
                        "client": client,
                        "available": self._remaining(state),
                        "required": tokens_needed,
                    },
                )

            state.tokens = max(0.0, state.tokens - tokens_needed)
            state.concurrent += 1
            self._stats["admitted"] += 1
            self._stats["tokens_spent"] += tokens_needed
            return Admission(
                fingerprint=fingerprint,
                depth=analysis.depth,
                cost=analysis.cost,
                client=client,
                remaining=self._remaining(state),
            )

    def admit_batch(
        self,
        queries,
        *,
        client: str = "default",
        now: float | None = None,
    ) -> list[Admission]:
        if isinstance(queries, (str, bytes)):
            raise GraphqlGuardError(
                "INVALID_QUERY",
                {"reason": "queries must be an iterable of query strings"},
            )
        try:
            query_list = list(queries)
        except TypeError as exc:
            raise GraphqlGuardError(
                "INVALID_QUERY",
                {"reason": "queries must be an iterable of query strings"},
            ) from exc

        with self._lock:
            timestamp = self._now(now)
            parsed = [self._parse_locked(query) for query in query_list]

            if self.strict_persisted:
                for _, fingerprint in parsed:
                    if fingerprint not in self._persisted:
                        raise GraphqlGuardError(
                            "PERSISTED_REQUIRED",
                            {
                                "reason": (
                                    "strict persisted-query mode requires every "
                                    "batch member to have an exactly registered "
                                    "fingerprint"
                                ),
                                "fingerprint": fingerprint,
                                "client": client,
                            },
                        )

            analyses = [
                self._analysis_locked(document) for document, _ in parsed
            ]
            for analysis in analyses:
                if (
                    analysis.introspection
                    and not self._policy["allow_introspection"]
                ):
                    raise GraphqlGuardError(
                        "INTROSPECTION_DENIED",
                        {
                            "reason": "introspection is disabled",
                            "allow_introspection": False,
                        },
                    )
                if analysis.depth > self.depth_limit:
                    raise GraphqlGuardError(
                        "DEPTH_EXCEEDED",
                        {
                            "reason": (
                                "batch member depth exceeds the configured limit"
                            ),
                            "actual": analysis.depth,
                            "limit": self.depth_limit,
                            "depth": analysis.depth,
                            "depth_limit": self.depth_limit,
                        },
                    )

            total_cost = sum(analysis.cost for analysis in analyses)
            if total_cost > self.cost_budget:
                raise GraphqlGuardError(
                    "BATCH_COST_EXCEEDED",
                    {
                        "reason": (
                            "total batch cost exceeds the configured budget"
                        ),
                        "actual": total_cost,
                        "limit": self.cost_budget,
                        "cost": total_cost,
                        "cost_budget": self.cost_budget,
                    },
                )

            state = self._client_locked(client, timestamp)
            required_slots = len(analyses)
            if state.concurrent + required_slots > self.max_concurrent:
                raise GraphqlGuardError(
                    "CONCURRENCY_LIMITED",
                    {
                        "reason": "client concurrency limit reached for batch",
                        "client": client,
                        "active": state.concurrent,
                        "required": required_slots,
                        "limit": self.max_concurrent,
                    },
                )

            tokens_needed = self._tokens_for_cost(total_cost)
            if state.tokens + 1e-9 < tokens_needed:
                raise GraphqlGuardError(
                    "RATE_LIMITED",
                    {
                        "reason": "client token bucket is exhausted for batch",
                        "client": client,
                        "available": self._remaining(state),
                        "required": tokens_needed,
                    },
                )

            state.tokens = max(0.0, state.tokens - tokens_needed)
            state.concurrent += required_slots
            self._stats["admitted"] += required_slots
            self._stats["tokens_spent"] += tokens_needed
            remaining = self._remaining(state)
            return [
                Admission(
                    fingerprint=fingerprint,
                    depth=analysis.depth,
                    cost=analysis.cost,
                    client=client,
                    remaining=remaining,
                )
                for (_, fingerprint), analysis in zip(parsed, analyses)
            ]

    def complete(self, client: str = "default") -> None:
        with self._lock:
            state = self._clients.get(client)
            if state is not None and state.concurrent > 0:
                state.concurrent -= 1

    def charge(
        self,
        client: str,
        cost: int,
        *,
        now: float | None = None,
    ) -> int:
        if not _is_int(cost) or cost < 0:
            raise GraphqlGuardError(
                "INVALID_COST",
                {
                    "reason": (
                        "charged token cost must be a non-negative integer"
                    )
                },
            )
        with self._lock:
            timestamp = self._now(now)
            state = self._client_locked(client, timestamp)
            if state.tokens + 1e-9 < cost:
                raise GraphqlGuardError(
                    "QUOTA_EXHAUSTED",
                    {
                        "reason": (
                            "charge would overdraw the client token bucket"
                        ),
                        "client": client,
                        "available": self._remaining(state),
                        "required": cost,
                    },
                )
            state.tokens = max(0.0, state.tokens - cost)
            self._stats["tokens_spent"] += cost
            return self._remaining(state)

    def status(self, client: str | None = None) -> dict:
        with self._lock:
            if client is not None:
                state = self._clients.get(client)
                if state is None:
                    return {
                        "client": client,
                        "tokens": self.burst,
                        "concurrent": 0,
                        "max_concurrent": self.max_concurrent,
                    }
                return {
                    "client": client,
                    "tokens": self._remaining(state),
                    "concurrent": state.concurrent,
                    "max_concurrent": self.max_concurrent,
                }

            clients = {
                name: {
                    "tokens": self._remaining(state),
                    "concurrent": state.concurrent,
                }
                for name, state in sorted(self._clients.items())
            }
            return {
                "clients": clients,
                "admitted": self._stats["admitted"],
                "tokens_spent": self._stats["tokens_spent"],
                "policy": copy.deepcopy(self._policy),
            }

    def policy(self, **changes) -> dict:
        with self._lock:
            if not changes:
                return copy.deepcopy(self._policy)

            candidate = copy.deepcopy(self._policy)
            for original_name, value in changes.items():
                name = _POLICY_ALIASES.get(original_name, original_name)
                if name == "allow_introspection":
                    if not isinstance(value, bool):
                        raise GraphqlGuardError(
                            "POLICY_INVALID",
                            {
                                "reason": (
                                    "allow_introspection must be a boolean"
                                ),
                                "field": original_name,
                            },
                        )
                    candidate[name] = value
                elif name == "field_weight":
                    if not _is_int(value) or value < 1:
                        raise GraphqlGuardError(
                            "POLICY_INVALID",
                            {
                                "reason": (
                                    "field_weight must be a positive integer"
                                ),
                                "field": original_name,
                            },
                        )
                    candidate[name] = value
                elif name == "field_weights":
                    if not isinstance(value, dict):
                        raise GraphqlGuardError(
                            "POLICY_INVALID",
                            {
                                "reason": "field_weights must be a mapping",
                                "field": original_name,
                            },
                        )
                    converted: dict[str, int] = {}
                    for field_name, weight in value.items():
                        if (
                            not isinstance(field_name, str)
                            or not field_name
                            or not _is_int(weight)
                            or weight < 1
                        ):
                            raise GraphqlGuardError(
                                "POLICY_INVALID",
                                {
                                    "reason": (
                                        "field_weights keys must be field "
                                        "names and values positive integers"
                                    ),
                                    "field": original_name,
                                },
                            )
                        converted[field_name] = weight
                    candidate[name] = converted
                elif name == "list_multiplier":
                    if not _is_int(value) or value < 1:
                        raise GraphqlGuardError(
                            "POLICY_INVALID",
                            {
                                "reason": (
                                    "list_multiplier must be a positive integer"
                                ),
                                "field": original_name,
                            },
                        )
                    candidate[name] = value
                elif name == "max_fragment_expansions":
                    if not _is_int(value) or value < 1:
                        raise GraphqlGuardError(
                            "POLICY_INVALID",
                            {
                                "reason": (
                                    "max_fragment_expansions must be a "
                                    "positive integer"
                                ),
                                "field": original_name,
                            },
                        )
                    candidate[name] = value
                elif name == "list_argument_names":
                    if isinstance(value, str) or not isinstance(
                        value, (list, tuple, set, frozenset)
                    ):
                        raise GraphqlGuardError(
                            "POLICY_INVALID",
                            {
                                "reason": (
                                    "list_argument_names must be an iterable "
                                    "of strings"
                                ),
                                "field": original_name,
                            },
                        )
                    names = set()
                    for item in value:
                        if not isinstance(item, str) or not item:
                            raise GraphqlGuardError(
                                "POLICY_INVALID",
                                {
                                    "reason": (
                                        "list_argument_names must contain "
                                        "non-empty strings"
                                    ),
                                    "field": original_name,
                                },
                            )
                        names.add(item.casefold())
                    candidate[name] = tuple(sorted(names))
                elif name == "refill_rate":
                    if not _is_number(value) or value < 0:
                        raise GraphqlGuardError(
                            "POLICY_INVALID",
                            {
                                "reason": (
                                    "refill_rate must be a non-negative number"
                                ),
                                "field": original_name,
                            },
                        )
                    candidate[name] = float(value)
                else:
                    raise GraphqlGuardError(
                        "POLICY_INVALID",
                        {
                            "reason": (
                                f"unknown policy setting {original_name!r}"
                            ),
                            "field": original_name,
                        },
                    )

            self._policy = candidate
            return copy.deepcopy(candidate)

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(
                {
                    "version": 1,
                    "config": {
                        "cost_budget": self.cost_budget,
                        "depth_limit": self.depth_limit,
                        "burst": self.burst,
                        "max_concurrent": self.max_concurrent,
                        "strict_persisted": self.strict_persisted,
                        "cost_per_token": self.cost_per_token,
                    },
                    "policy": self._policy,
                    "persisted": sorted(self._persisted),
                    "clients": {
                        name: {
                            "tokens": state.tokens,
                            "last_refill": state.last_refill,
                            "concurrent": state.concurrent,
                        }
                        for name, state in self._clients.items()
                    },
                    "stats": self._stats,
                }
            )

    def restore(self, state: dict) -> None:
        try:
            candidate = copy.deepcopy(state)
            if not isinstance(candidate, dict):
                raise ValueError("snapshot must be a mapping")
            if candidate.get("version") != 1:
                raise ValueError("unsupported snapshot version")

            config = candidate["config"]
            policy = candidate["policy"]
            persisted = candidate["persisted"]
            clients = candidate["clients"]
            stats = candidate["stats"]

            if not isinstance(config, dict):
                raise ValueError("config must be a mapping")
            cost_budget = config["cost_budget"]
            depth_limit = config["depth_limit"]
            burst = config["burst"]
            max_concurrent = config["max_concurrent"]
            strict_persisted = config["strict_persisted"]
            cost_per_token = config["cost_per_token"]
            if not _is_int(cost_budget) or cost_budget < 0:
                raise ValueError("invalid cost_budget")
            if not _is_int(depth_limit) or depth_limit < 0:
                raise ValueError("invalid depth_limit")
            if not _is_int(burst) or burst < 0:
                raise ValueError("invalid burst")
            if not _is_int(max_concurrent) or max_concurrent < 0:
                raise ValueError("invalid max_concurrent")
            if not isinstance(strict_persisted, bool):
                raise ValueError("invalid strict_persisted")
            if not _is_int(cost_per_token) or cost_per_token < 1:
                raise ValueError("invalid cost_per_token")

            if not isinstance(policy, dict):
                raise ValueError("policy must be a mapping")
            allow_introspection = policy["allow_introspection"]
            field_weight = policy["field_weight"]
            field_weights = policy["field_weights"]
            list_multiplier = policy["list_multiplier"]
            max_fragment_expansions = policy["max_fragment_expansions"]
            list_argument_names = policy["list_argument_names"]
            refill_rate = policy["refill_rate"]
            if not isinstance(allow_introspection, bool):
                raise ValueError("invalid allow_introspection")
            if not _is_int(field_weight) or field_weight < 1:
                raise ValueError("invalid field_weight")
            if not isinstance(field_weights, dict):
                raise ValueError("invalid field_weights")
            normalized_weights: dict[str, int] = {}
            for field_name, weight in field_weights.items():
                if (
                    not isinstance(field_name, str)
                    or not field_name
                    or not _is_int(weight)
                    or weight < 1
                ):
                    raise ValueError("invalid field_weights entry")
                normalized_weights[field_name] = weight
            if not _is_int(list_multiplier) or list_multiplier < 1:
                raise ValueError("invalid list_multiplier")
            if (
                not _is_int(max_fragment_expansions)
                or max_fragment_expansions < 1
            ):
                raise ValueError("invalid max_fragment_expansions")
            if isinstance(list_argument_names, str) or not isinstance(
                list_argument_names, (list, tuple, set, frozenset)
            ):
                raise ValueError("invalid list_argument_names")
            normalized_argument_names: set[str] = set()
            for item in list_argument_names:
                if not isinstance(item, str) or not item:
                    raise ValueError("invalid list_argument_names entry")
                normalized_argument_names.add(item.casefold())
            if not _is_number(refill_rate) or refill_rate < 0:
                raise ValueError("invalid refill_rate")

            if isinstance(persisted, (str, bytes)) or not isinstance(
                persisted, (list, tuple)
            ):
                raise ValueError("persisted must be a sequence")
            normalized_persisted: set[str] = set()
            for item in persisted:
                if not isinstance(item, str) or not item:
                    raise ValueError("invalid persisted fingerprint")
                normalized_persisted.add(item)

            if not isinstance(clients, dict):
                raise ValueError("clients must be a mapping")
            normalized_clients: dict[str, _ClientState] = {}
            for name, client_state in clients.items():
                if not isinstance(name, str) or not isinstance(
                    client_state, dict
                ):
                    raise ValueError("invalid client state")
                tokens = client_state["tokens"]
                last_refill = client_state["last_refill"]
                concurrent = client_state["concurrent"]
                if (
                    not _is_number(tokens)
                    or tokens < 0
                    or tokens > float(burst) + 1e-9
                ):
                    raise ValueError("invalid client token level")
                if not _is_number(last_refill):
                    raise ValueError("invalid client refill timestamp")
                if (
                    not _is_int(concurrent)
                    or concurrent < 0
                    or concurrent > max_concurrent
                ):
                    raise ValueError("invalid client concurrency level")
                normalized_clients[name] = _ClientState(
                    float(tokens), float(last_refill), concurrent
                )

            if not isinstance(stats, dict):
                raise ValueError("stats must be a mapping")
            admitted = stats["admitted"]
            tokens_spent = stats["tokens_spent"]
            if not _is_int(admitted) or admitted < 0:
                raise ValueError("invalid admitted statistic")
            if not _is_int(tokens_spent) or tokens_spent < 0:
                raise ValueError("invalid tokens_spent statistic")

            normalized_policy = {
                "allow_introspection": allow_introspection,
                "field_weight": field_weight,
                "field_weights": normalized_weights,
                "list_multiplier": list_multiplier,
                "max_fragment_expansions": max_fragment_expansions,
                "list_argument_names": tuple(
                    sorted(normalized_argument_names)
                ),
                "refill_rate": float(refill_rate),
            }
            normalized_stats = {
                "admitted": admitted,
                "tokens_spent": tokens_spent,
            }
        except (
            KeyError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
        ) as exc:
            raise GraphqlGuardError(
                "SNAPSHOT_INVALID",
                {
                    "reason": "snapshot structure is invalid",
                    "error": str(exc),
                },
            ) from exc

        with self._lock:
            self.cost_budget = cost_budget
            self.depth_limit = depth_limit
            self.burst = burst
            self.max_concurrent = max_concurrent
            self.strict_persisted = strict_persisted
            self.cost_per_token = cost_per_token
            self._policy = normalized_policy
            self._persisted = normalized_persisted
            self._clients = normalized_clients
            self._stats = normalized_stats

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

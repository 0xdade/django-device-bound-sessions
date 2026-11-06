"""Reading and writing the DBSC HTTP headers.

The DBSC spec defines all of its headers as Structured Field Values
(RFC 9651), which has exact rules for quoting, escaping, lists and
``;key=value`` parameters:

* ``Secure-Session-Registration`` (we send):
  ``(ES256 RS256);path="/dbsc/register/";challenge="..."``
* ``Secure-Session-Challenge`` (we send): ``"<challenge>";id="<session id>"``
* ``Sec-Secure-Session-Id`` (browser sends): ``"<session id>"``
* ``Secure-Session-Response`` (browser sends): ``"<proof JWT>"``

This module implements only what those headers use: strings and tokens as
values, inner lists, and parameters with string or token values. Other
RFC 9651 types (integers, decimals, booleans, byte sequences, dates) never
appear in DBSC and are not supported.

* Writing (``serialize_*``) escapes values and rejects anything that can't be
  represented, so a header we send is always well-formed.
* Reading what the browser sends (:func:`parse_string_item`) is strict about
  the value itself, so malformed input is rejected rather than half-read.
* :func:`parse_list` reads full list headers. The server never needs it; the
  ``DBSCBrowser`` test helper uses it to read our headers as a browser would.
"""

import string


class StructuredFieldError(ValueError):
    """A header value isn't valid, or can't be written, as a structured field."""


class Token(str):
    """A structured-field token, written unquoted (e.g. ``ES256``).

    A plain ``str`` is written as a quoted string instead.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return f"Token({str.__repr__(self)})"


#: Parameters, e.g. ``;path="/x";challenge="y"`` -> ``{"path": "/x", "challenge": "y"}``.
type Params = dict[str, str]
#: A value with its parameters.
type Item = tuple[str, Params]
#: ``(a b);p="v"`` -> ``([("a", {}), ("b", {})], {"p": "v"})``.
type InnerList = tuple[list[Item], Params]
type ListMember = Item | InnerList


_TOKEN_START = set(string.ascii_letters + "*")
_TOKEN_CHAR = set(string.ascii_letters + string.digits + "!#$%&'*+-.^_`|~:/")
_KEY_START = set(string.ascii_lowercase + "*")
_KEY_CHAR = set(string.ascii_lowercase + string.digits + "_-.*")


def _is_printable_ascii(ch: str) -> bool:
    return 0x20 <= ord(ch) <= 0x7E


# --------------------------------------------------------------------------
# Writing (headers we send)
# --------------------------------------------------------------------------


def serialize_string(value: str) -> str:
    """``ab"c`` -> ``"ab\\"c"``."""
    out = ['"']
    for ch in value:
        if not _is_printable_ascii(ch):
            raise StructuredFieldError(f"Character not allowed in a string: {ch!r}")
        if ch in '\\"':
            out.append("\\")
        out.append(ch)
    out.append('"')
    return "".join(out)


def serialize_token(value: str) -> str:
    if not value or value[0] not in _TOKEN_START or any(c not in _TOKEN_CHAR for c in value):
        raise StructuredFieldError(f"Invalid token: {value!r}")
    return value


def _serialize_value(value: str) -> str:
    return serialize_token(value) if isinstance(value, Token) else serialize_string(value)


def serialize_params(params: Params) -> str:
    out: list[str] = []
    for key, value in params.items():
        if not key or key[0] not in _KEY_START or any(c not in _KEY_CHAR for c in key):
            raise StructuredFieldError(f"Invalid parameter key: {key!r}")
        out.append(f";{key}={_serialize_value(value)}")
    return "".join(out)


def serialize_item(value: str, params: Params | None = None) -> str:
    """``serialize_item("c", {"id": "s"})`` -> ``"c";id="s"``."""
    return _serialize_value(value) + serialize_params(params or {})


def serialize_inner_list(items: list[str], params: Params | None = None) -> str:
    """``serialize_inner_list([Token("ES256")], {"path": "/r"})`` -> ``(ES256);path="/r"``."""
    inner = " ".join(_serialize_value(item) for item in items)
    return f"({inner}){serialize_params(params or {})}"


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------


def parse_string_item(value: str) -> str:
    """Read a header whose value is a single string, as DBSC request headers are.

    A bare token is accepted too: Chrome's docs show the proof JWT unquoted.
    Parameters after the value are ignored without being interpreted, as the
    spec says they SHOULD be, so a future parameter can't break us. Anything
    else after the value is an error.
    """
    parser = _Parser(value.strip(" "))
    if parser.peek() == '"':
        result = parser.parse_string()
    elif parser.peek() in _TOKEN_START and parser.peek():
        result = str(parser.parse_token())
    else:
        raise StructuredFieldError("Expected a string")
    if not (parser.done() or parser.peek() == ";"):
        raise StructuredFieldError("Unexpected characters after the value")
    return result


def parse_list(value: str) -> list[ListMember]:
    """Read a list header: ``[(value_or_inner_list, params), ...]``."""
    parser = _Parser(value.strip(" "))
    return parser.parse_list()


class _Parser:
    def __init__(self, value: str) -> None:
        self.s = value
        self.i = 0

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def done(self) -> bool:
        return self.i >= len(self.s)

    def skip_spaces(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_whitespace(self) -> None:
        while self.peek() in (" ", "\t") and self.peek():
            self.i += 1

    def parse_list(self) -> list[ListMember]:
        members: list[ListMember] = []
        while not self.done():
            members.append(self.parse_inner_list() if self.peek() == "(" else self.parse_item())
            self.skip_whitespace()
            if self.done():
                break
            if self.peek() != ",":
                raise StructuredFieldError("Expected ',' between list members")
            self.i += 1
            self.skip_whitespace()
            if self.done():
                raise StructuredFieldError("Trailing comma in list")
        return members

    def parse_inner_list(self) -> InnerList:
        self.i += 1  # "("
        items: list[Item] = []
        while not self.done():
            self.skip_spaces()
            if self.peek() == ")":
                self.i += 1
                return items, self.parse_params()
            items.append(self.parse_item())
            if self.peek() not in (" ", ")"):
                raise StructuredFieldError("Expected ' ' or ')' in inner list")
        raise StructuredFieldError("Unterminated inner list")

    def parse_item(self) -> Item:
        return self.parse_value(), self.parse_params()

    def parse_value(self) -> str:
        ch = self.peek()
        if ch == '"':
            return self.parse_string()
        if ch in _TOKEN_START and ch:
            return self.parse_token()
        raise StructuredFieldError(f"Expected a string or token, found {ch!r}")

    def parse_string(self) -> str:
        self.i += 1  # opening quote
        out: list[str] = []
        while not self.done():
            ch = self.s[self.i]
            self.i += 1
            if ch == "\\":
                if self.done():
                    raise StructuredFieldError("Dangling escape")
                escaped = self.s[self.i]
                self.i += 1
                if escaped not in '\\"':
                    raise StructuredFieldError("Invalid escape")
                out.append(escaped)
            elif ch == '"':
                return "".join(out)
            elif not _is_printable_ascii(ch):
                raise StructuredFieldError("Invalid character in string")
            else:
                out.append(ch)
        raise StructuredFieldError("Unterminated string")

    def parse_token(self) -> Token:
        start = self.i
        self.i += 1
        while self.peek() and self.peek() in _TOKEN_CHAR:
            self.i += 1
        return Token(self.s[start : self.i])

    def parse_params(self) -> Params:
        params: Params = {}
        while self.peek() == ";":
            self.i += 1
            self.skip_spaces()
            key = self.parse_key()
            if self.peek() != "=":
                raise StructuredFieldError(f"Parameter {key!r} has no value")
            self.i += 1
            params[key] = self.parse_value()
        return params

    def parse_key(self) -> str:
        if not self.peek() or self.peek() not in _KEY_START:
            raise StructuredFieldError("Invalid parameter key")
        start = self.i
        while self.peek() and self.peek() in _KEY_CHAR:
            self.i += 1
        return self.s[start : self.i]

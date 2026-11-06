"""Minimal RFC 9651 structured-field support for the DBSC headers.

Only the subset DBSC uses is implemented: lists of items and inner lists,
with strings, tokens, integers and booleans as bare items and parameters.
"""

import string


class SFError(ValueError):
    pass


class Token(str):
    """A structured-field token (as opposed to a string)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return f"Token({str.__repr__(self)})"


#: A bare item: sf-string (``str``), sf-token (:class:`Token`), integer or boolean.
type BareItem = str | int | bool
type Params = dict[str, BareItem]
type Item = tuple[BareItem, Params]
type InnerList = tuple[list[Item], Params]
type ListMember = Item | InnerList


_TOKEN_START = set(string.ascii_letters + "*")
_TCHAR = set(string.ascii_letters + string.digits + "!#$%&'*+-.^_`|~:/")
_KEY_START = set(string.ascii_lowercase + "*")
_KEY_CHAR = set(string.ascii_lowercase + string.digits + "_-.*")


# --------------------------------------------------------------------------
# Serialization
# --------------------------------------------------------------------------


def serialize_string(value: str) -> str:
    out = ['"']
    for ch in value:
        if not (0x20 <= ord(ch) <= 0x7E):
            raise SFError(f"Character not allowed in sf-string: {ch!r}")
        if ch in '\\"':
            out.append("\\")
        out.append(ch)
    out.append('"')
    return "".join(out)


def serialize_token(value: str) -> str:
    if not value or value[0] not in _TOKEN_START or any(c not in _TCHAR for c in value):
        raise SFError(f"Invalid sf-token: {value!r}")
    return value


def serialize_bare_item(value: BareItem) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Token):
        return serialize_token(value)
    return serialize_string(value)


def serialize_params(params: Params) -> str:
    out: list[str] = []
    for key, value in params.items():
        if not key or key[0] not in _KEY_START or any(c not in _KEY_CHAR for c in key):
            raise SFError(f"Invalid parameter key: {key!r}")
        out.append(f";{key}")
        if value is not True:
            out.append(f"={serialize_bare_item(value)}")
    return "".join(out)


def serialize_item(value: BareItem, params: Params | None = None) -> str:
    return serialize_bare_item(value) + serialize_params(params or {})


def serialize_inner_list(items: list[BareItem], params: Params | None = None) -> str:
    inner = " ".join(serialize_bare_item(i) for i in items)
    return f"({inner}){serialize_params(params or {})}"


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


class _Parser:
    def __init__(self, value: str) -> None:
        self.s = value
        self.i = 0

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t") and self.peek():
            self.i += 1

    def done(self) -> bool:
        return self.i >= len(self.s)

    def parse_list(self) -> list[ListMember]:
        members: list[ListMember] = []
        self.skip_sp()
        while not self.done():
            members.append(self.parse_item_or_inner_list())
            self.skip_ows()
            if self.done():
                return members
            if self.peek() != ",":
                raise SFError("Expected ',' in list")
            self.i += 1
            self.skip_ows()
            if self.done():
                raise SFError("Trailing comma in list")
        return members

    def parse_item_or_inner_list(self) -> ListMember:
        if self.peek() == "(":
            return self.parse_inner_list()
        return self.parse_item()

    def parse_inner_list(self) -> InnerList:
        self.i += 1  # (
        items: list[Item] = []
        while not self.done():
            self.skip_sp()
            if self.peek() == ")":
                self.i += 1
                return items, self.parse_params()
            items.append(self.parse_item())
            if self.peek() not in (" ", ")"):
                raise SFError("Expected ' ' or ')' in inner list")
        raise SFError("Unterminated inner list")

    def parse_item(self) -> Item:
        value = self.parse_bare_item()
        return value, self.parse_params()

    def parse_bare_item(self) -> BareItem:
        ch = self.peek()
        if ch == '"':
            return self.parse_string()
        if ch in _TOKEN_START and ch:
            return self.parse_token()
        if ch == "?":
            return self.parse_boolean()
        if ch == "-" or ch.isdigit():
            return self.parse_integer()
        raise SFError(f"Unexpected character {ch!r}")

    def parse_string(self) -> str:
        self.i += 1
        out: list[str] = []
        while not self.done():
            ch = self.s[self.i]
            self.i += 1
            if ch == "\\":
                if self.done():
                    raise SFError("Dangling escape")
                nxt = self.s[self.i]
                self.i += 1
                if nxt not in '\\"':
                    raise SFError("Invalid escape")
                out.append(nxt)
            elif ch == '"':
                return "".join(out)
            elif not (0x20 <= ord(ch) <= 0x7E):
                raise SFError("Invalid character in string")
            else:
                out.append(ch)
        raise SFError("Unterminated string")

    def parse_token(self) -> Token:
        start = self.i
        self.i += 1
        while self.peek() and self.peek() in _TCHAR:
            self.i += 1
        return Token(self.s[start : self.i])

    def parse_boolean(self) -> bool:
        self.i += 1
        ch = self.peek()
        if ch not in ("0", "1") or not ch:
            raise SFError("Invalid boolean")
        self.i += 1
        return ch == "1"

    def parse_integer(self) -> int:
        start = self.i
        if self.peek() == "-":
            self.i += 1
        while self.peek() and self.peek().isdigit():
            self.i += 1
        digits = self.s[start : self.i]
        if digits in ("", "-") or len(digits.lstrip("-")) > 15:
            raise SFError("Invalid integer")
        return int(digits)

    def parse_params(self) -> Params:
        params: Params = {}
        while self.peek() == ";":
            self.i += 1
            self.skip_sp()
            key = self.parse_key()
            value: BareItem = True
            if self.peek() == "=":
                self.i += 1
                value = self.parse_bare_item()
            params[key] = value
        return params

    def parse_key(self) -> str:
        if not self.peek() or self.peek() not in _KEY_START:
            raise SFError("Invalid parameter key")
        start = self.i
        while self.peek() and self.peek() in _KEY_CHAR:
            self.i += 1
        return self.s[start : self.i]


def parse_list(value: str) -> list[ListMember]:
    """Parse an sf-list. Returns ``[(item_or_list_of_items, params), ...]``."""
    p = _Parser(value.strip(" "))
    return p.parse_list()


def parse_string_item(value: str) -> tuple[str, Params]:
    """Parse an sf-item that must be a string (a bare token is accepted too).

    Returns ``(value, params)`` with the value as a plain ``str``.
    """
    item, params = parse_item(value)
    if not isinstance(item, str):
        raise SFError("Expected a string")
    return str(item), params


def parse_item(value: str) -> Item:
    """Parse an sf-item. Returns ``(bare_item, params)``."""
    p = _Parser(value.strip(" "))
    result = p.parse_item()
    p.skip_sp()
    if not p.done():
        raise SFError("Trailing characters after item")
    return result

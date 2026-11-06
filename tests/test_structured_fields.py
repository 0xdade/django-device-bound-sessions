"""Reading and writing the DBSC headers (RFC 9651 structured fields)."""

import re

import pytest

from django_device_bound_sessions.structured_fields import (
    StructuredFieldError,
    Token,
    parse_list,
    parse_string_item,
    serialize_inner_list,
    serialize_item,
    serialize_params,
    serialize_string,
    serialize_token,
)

# --- Writing: the two headers we send ----------------------------------------


def test_registration_header():
    value = serialize_inner_list(
        [Token("ES256"), Token("RS256")], {"path": "/dbsc/register/", "challenge": "a:b"}
    )
    assert value == '(ES256 RS256);path="/dbsc/register/";challenge="a:b"'


def test_challenge_header():
    assert serialize_item("chal", {"id": "sess"}) == '"chal";id="sess"'


def test_string_escapes():
    assert serialize_string('a"b\\c') == '"a\\"b\\\\c"'


def test_tokens_are_unquoted_and_strings_quoted():
    assert serialize_item(Token("ES256")) == "ES256"
    assert serialize_item("ES256") == '"ES256"'


@pytest.mark.parametrize("value", ["tab\there", "naïve", "new\nline"])
def test_strings_must_be_printable_ascii(value):
    with pytest.raises(StructuredFieldError, match="not allowed"):
        serialize_string(value)


@pytest.mark.parametrize("value", ["", "1abc", "has space"])
def test_invalid_tokens(value):
    with pytest.raises(StructuredFieldError, match="Invalid token"):
        serialize_token(value)


@pytest.mark.parametrize("key", ["", "Upper", "1st", "sp ace"])
def test_invalid_parameter_keys(key):
    with pytest.raises(StructuredFieldError, match="Invalid parameter key"):
        serialize_params({key: "v"})


def test_token_repr():
    assert repr(Token("ES256")) == "Token('ES256')"


# --- Reading what the browser sends -------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ('"session-id"', "session-id"),
        ('  "padded"  ', "padded"),
        ('"esc\\"aped"', 'esc"aped'),
        # Chrome's docs show the proof JWT unquoted, so a bare token is accepted.
        ("eyJhbGciOi.eyJqdGkiOi.sig-_x", "eyJhbGciOi.eyJqdGkiOi.sig-_x"),
    ],
)
def test_parse_string_item(header, expected):
    assert parse_string_item(header) == expected


@pytest.mark.parametrize(
    "header",
    [
        '"id";v=1',  # an integer: a type we don't parse
        '"id";v=1.5',  # a decimal
        '"id";flag',  # a parameter with no value
        '"id";a="x";b=?1',
    ],
)
def test_parameters_are_ignored_without_being_parsed(header):
    """The spec says parameters SHOULD be ignored; new ones must not break us."""
    assert parse_string_item(header) == "id"


@pytest.mark.parametrize(
    ("header", "message"),
    [
        ("", "Expected a string"),
        ("?1", "Expected a string"),
        ("12", "Expected a string"),
        ("(inner list)", "Expected a string"),
        ('"a" "b"', "Unexpected characters after the value"),
        ('"abc"x', "Unexpected characters after the value"),
        ('"unterminated', "Unterminated string"),
        ('"a\\', "Dangling escape"),
        ('"bad\\x"', "Invalid escape"),
        ('"a\tb"', "Invalid character"),
    ],
)
def test_parse_string_item_rejects(header, message):
    with pytest.raises(StructuredFieldError, match=re.escape(message)):
        parse_string_item(header)


# --- Reading full lists (used by the DBSCBrowser test helper) -----------------


@pytest.mark.parametrize(
    "header",
    [
        '(ES256);path="reg";challenge="cv";authorization="ac"',
        '(ES256 RS256);path="reg";challenge="cv"',
        (
            '(ES256);path="reg1";challenge="cv1";authorization="a", '
            '(RS256);path="reg2";challenge="cv2";authorization="b"'
        ),
        '(ES256 RS256); path="/StartSession"',
    ],
)
def test_spec_registration_examples(header):
    members = parse_list(header)
    assert members
    for items, params in members:
        assert isinstance(items, list)
        assert "path" in params


def test_registration_header_round_trip():
    header = serialize_inner_list(
        [Token("ES256"), Token("RS256")], {"path": "/r", "challenge": "c"}
    )
    [(items, params)] = parse_list(header)
    assert items == [("ES256", {}), ("RS256", {})]
    assert params == {"path": "/r", "challenge": "c"}


def test_challenges_for_several_sessions():
    members = parse_list('"c1";id="session 1", "c2";id="session 2"')
    assert members == [("c1", {"id": "session 1"}), ("c2", {"id": "session 2"})]


def test_empty_list():
    assert parse_list("") == []
    assert parse_list("   ") == []


def test_whitespace_around_list_members():
    assert parse_list('  "a" ,\t"b"  ') == [("a", {}), ("b", {})]


@pytest.mark.parametrize(
    ("header", "message"),
    [
        ('"a" "b"', "Expected ','"),
        ('"a",', "Trailing comma"),
        ("(", "Unterminated inner list"),
        ("(a b", "Expected ' ' or ')'"),
        ("(a,b)", "Expected ' ' or ')'"),
        ('"a";flag', "has no value"),
        ('"a";Bad="x"', "Invalid parameter key"),
        ("@", "Expected a string or token"),
        ("1", "Expected a string or token"),
    ],
)
def test_parse_list_rejects(header, message):
    with pytest.raises(StructuredFieldError, match=re.escape(message)):
        parse_list(header)

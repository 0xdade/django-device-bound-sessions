import re

import pytest

from django_device_bound_sessions import sf


def test_registration_header_roundtrip():
    value = sf.serialize_inner_list(
        [sf.Token("ES256"), sf.Token("RS256")], {"path": "/dbsc/register/", "challenge": "a:b"}
    )
    assert value == '(ES256 RS256);path="/dbsc/register/";challenge="a:b"'
    [(items, _params)] = sf.parse_list(value)
    assert items == [("ES256", {}), ("RS256", {})]


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
def test_parse_spec_registration_examples(header):
    members = sf.parse_list(header)
    assert members
    for items, params in members:
        assert isinstance(items, list)
        assert "path" in params


def test_parse_challenge_with_multiple_sessions():
    members = sf.parse_list('"c1";id="session 1", "c2";id="session 2"')
    assert members == [("c1", {"id": "session 1"}), ("c2", {"id": "session 2"})]


def test_string_escapes():
    assert sf.serialize_string('a"b\\c') == '"a\\"b\\\\c"'
    assert sf.parse_item('"a\\"b\\\\c"') == ('a"b\\c', {})


def test_bare_jwt_parses_as_token():
    jwt_like = "eyJhbGciOi.eyJqdGkiOi.sig-_x"
    value, _ = sf.parse_item(jwt_like)
    assert value == jwt_like
    assert isinstance(value, sf.Token)


@pytest.mark.parametrize("bad", ['"unterminated', "(ES256", '"bad\\x"', ""])
def test_parse_errors(bad):
    with pytest.raises(sf.SFError):
        sf.parse_list(bad) if bad.startswith("(") else sf.parse_item(bad)


# --- Bare item types DBSC doesn't use, but the parser accepts --------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, "?1"),
        (False, "?0"),
        (42, "42"),
        (-7, "-7"),
        (sf.Token("ES256"), "ES256"),
        ("a", '"a"'),
    ],
)
def test_serialize_bare_items(value, expected):
    assert sf.serialize_bare_item(value) == expected


@pytest.mark.parametrize(
    ("header", "expected"),
    [("?1", True), ("?0", False), ("42", 42), ("-7", -7), ('"s";flag', "s")],
)
def test_parse_bare_items(header, expected):
    value, _params = sf.parse_item(header)
    assert value == expected


def test_boolean_parameters_round_trip():
    serialized = sf.serialize_item("v", {"a": True, "b": False, "n": 3})
    assert serialized == '"v";a;b=?0;n=3'
    assert sf.parse_item(serialized) == ("v", {"a": True, "b": False, "n": 3})


def test_token_repr():
    assert repr(sf.Token("ES256")) == "Token('ES256')"


# --- Serialization errors -----------------------------------------------------


@pytest.mark.parametrize("value", ["tab\there", "naïve", "new\nline"])
def test_serialize_string_rejects_non_printable_ascii(value):
    with pytest.raises(sf.SFError, match="not allowed"):
        sf.serialize_string(value)


@pytest.mark.parametrize("value", ["", "1abc", "has space"])
def test_serialize_token_rejects_invalid(value):
    with pytest.raises(sf.SFError, match="Invalid sf-token"):
        sf.serialize_token(value)


@pytest.mark.parametrize("key", ["", "Upper", "1st", "sp ace"])
def test_serialize_params_rejects_invalid_keys(key):
    with pytest.raises(sf.SFError, match="Invalid parameter key"):
        sf.serialize_params({key: "v"})


# --- Parse errors ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "message"),
    [
        ('"a" "b"', "Expected ','"),
        ('"a",', "Trailing comma"),
        ("(", "Unterminated inner list"),
        ("(a b", "Expected ' ' or ')'"),
        ("(a,b)", "Expected ' ' or ')'"),
        ('"a\\', "Dangling escape"),
        ('"a\tb"', "Invalid character"),
        ("?2", "Invalid boolean"),
        ("?", "Invalid boolean"),
        ("-", "Invalid integer"),
        ("1234567890123456", "Invalid integer"),
        ('"a";Bad=1', "Invalid parameter key"),
        ("@", "Unexpected character"),
    ],
)
def test_parse_list_errors(header, message):
    with pytest.raises(sf.SFError, match=re.escape(message)):
        sf.parse_list(header)


def test_parse_item_rejects_trailing_characters():
    with pytest.raises(sf.SFError, match="Trailing characters"):
        sf.parse_item('"a" "b"')


def test_parse_string_item_rejects_non_strings():
    with pytest.raises(sf.SFError, match="Expected a string"):
        sf.parse_string_item("?1")


def test_empty_list():
    """An empty header value is an empty list (RFC 9651)."""
    assert sf.parse_list("") == []
    assert sf.parse_list("   ") == []


def test_whitespace_around_list_members():
    assert sf.parse_list('  "a" ,\t"b"  ') == [("a", {}), ("b", {})]

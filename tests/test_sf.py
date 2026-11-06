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

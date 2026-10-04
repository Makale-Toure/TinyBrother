import base64

import pytest

from tinybrother.engine.errors import UnsupportedRule
from tinybrother.engine.modifiers import compile_value


def m(value, mods, field):
    return compile_value(value, mods)(field)


def test_equals_is_case_insensitive():
    assert m("Admin", [], "admin")
    assert not m("Admin", [], "administrator")


def test_cased():
    assert not m("Admin", ["cased"], "admin")
    assert m("Admin", ["cased"], "Admin")


@pytest.mark.parametrize("mod, value, field, ok", [
    ("contains", "mimikatz", "C:\\Tools\\MIMIKATZ.exe", True),
    ("startswith", "C:\\Windows\\", "c:\\windows\\system32\\cmd.exe", True),
    ("endswith", "\\cmd.exe", "C:\\Windows\\System32\\cmd.exe", True),
    ("endswith", "\\cmd.exe", "C:\\cmd.exe.bak", False),
])
def test_string_modifiers(mod, value, field, ok):
    assert m(value, [mod], field) is ok


def test_wildcards_and_escapes():
    assert m("*\\powershell.exe", [], "C:\\Windows\\powershell.exe")
    assert m("cmd.ex?", [], "cmd.exe")
    assert not m("a\\*b", [], "axxb")
    assert m("a\\*b", [], "a*b")


def test_list_is_or_and_all_is_and():
    assert m(["foo", "bar"], ["contains"], "xxbarxx")
    assert not m(["foo", "bar"], ["contains", "all"], "xxbarxx")
    assert m(["foo", "bar"], ["contains", "all"], "foo bar")


def test_null_matches_missing_or_empty():
    assert m(None, [], None)
    assert m(None, [], "")
    assert not m(None, [], "x")


def test_missing_field_never_matches_a_value():
    assert not m("x", ["contains"], None)


def test_numbers_compare_as_strings():
    assert m(4688, [], "4688")


def test_regex_and_flags():
    assert m(r"\s-enc\s", ["re"], "powershell -enc AAAA")
    assert not m("ABC", ["re"], "abc")
    assert m("ABC", ["re", "i"], "abc")


def test_cidr():
    assert m("10.0.0.0/8", ["cidr"], "10.1.2.3")
    assert not m("10.0.0.0/8", ["cidr"], "192.168.1.1")
    assert not m("10.0.0.0/8", ["cidr"], "not-an-ip")


def test_numeric_comparisons():
    assert m(5, ["gt"], "10")
    assert not m(5, ["lt"], "10")


def test_exists():
    assert m(True, ["exists"], "x")
    assert not m(True, ["exists"], None)
    assert m(False, ["exists"], None)


def test_windash():
    pred = compile_value(" -enc ", ["windash", "contains"])
    assert pred("powershell -enc AAA")
    assert pred("powershell /enc AAA")
    assert pred("powershell \u2013enc AAA")


def test_base64offset_finds_payload_at_any_alignment():
    pred = compile_value("http://", ["base64offset", "contains"])
    for prefix in ("", "a", "ab"):
        encoded = base64.b64encode((prefix + "http://evil").encode()).decode()
        assert pred(f"powershell -e {encoded}")


def test_wide_base64offset():
    pred = compile_value("IEX", ["wide", "base64offset", "contains"])
    payload = base64.b64encode("IEX (New-Object Net.WebClient)".encode("utf-16-le")).decode()
    assert pred(payload)


def test_unknown_modifier_is_rejected():
    with pytest.raises(UnsupportedRule):
        compile_value("x", ["expand_me"])

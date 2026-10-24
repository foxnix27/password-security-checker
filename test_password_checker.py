import pytest

from password_checker import check_password, has_repeated_chars, has_sequence


def test_common_password_is_weak():
    strength, suggestions = check_password("password")
    assert strength == "WEAK"
    assert suggestions


def test_short_simple_password_is_weak():
    strength, _ = check_password("abc")
    assert strength == "WEAK"


def test_medium_password():
    strength, _ = check_password("Hello123")
    assert strength == "MEDIUM"


def test_strong_password_has_no_suggestions():
    strength, suggestions = check_password("T7#rQz!m9Lp2")
    assert strength == "STRONG"
    assert suggestions == []


def test_repeated_chars_detected():
    assert has_repeated_chars("aaab")
    assert not has_repeated_chars("aabb")


def test_sequence_detected():
    assert has_sequence("xx1234xx")
    assert has_sequence("QWERty")
    assert has_sequence("dcba")
    assert not has_sequence("a1b2c3")


def test_patterns_lower_the_score():
    plain, _ = check_password("Tr7#kp9Lm2Xz")
    patterned, suggestions = check_password("Tr7#aaaa1234")
    order = ["WEAK", "MEDIUM", "STRONG"]
    assert order.index(patterned) < order.index(plain)
    assert any("repeating" in s for s in suggestions)
    assert any("sequences" in s for s in suggestions)

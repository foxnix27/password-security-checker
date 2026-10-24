import pytest

import string
import urllib.error

from password_checker import (
    COMMON_PASSWORDS,
    check_password,
    check_pwned,
    generate_password,
    has_repeated_chars,
    has_sequence,
    load_common_passwords,
)


def test_short_password_always_gets_length_suggestion():
    # 8-11 character passwords used to get no length advice
    _, suggestions = check_password("Zebra835")
    assert "Use at least 12 characters." in suggestions


def test_generate_password_length_and_character_classes():
    for length in (8, 16, 32):
        password = generate_password(length)
        assert len(password) == length
        assert any(c in string.ascii_lowercase for c in password)
        assert any(c in string.ascii_uppercase for c in password)
        assert any(c in string.digits for c in password)
        assert any(c not in string.ascii_letters + string.digits for c in password)


def test_generate_password_is_strong_and_random():
    first, second = generate_password(), generate_password()
    assert check_password(first)[0] == "STRONG"
    assert first != second


def test_generate_password_rejects_too_short_length():
    try:
        generate_password(4)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


class FakeResponse:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_check_pwned_found_and_only_sends_prefix():
    seen = {}

    def fake_opener(request, timeout):
        seen["url"] = request.full_url
        return FakeResponse(f"0000000000000000000000000000000000A:3\r\n{PASSWORD_SUFFIX}:12345\r\n")

    assert check_pwned("password", opener=fake_opener) == 12345
    assert seen["url"].endswith("/range/5BAA6")
    assert PASSWORD_SUFFIX not in seen["url"]


def test_check_pwned_not_found_returns_zero():
    def fake_opener(request, timeout):
        return FakeResponse("0000000000000000000000000000000000A:3\r\n")

    assert check_pwned("password", opener=fake_opener) == 0


def test_check_pwned_padding_entries_count_as_zero():
    def fake_opener(request, timeout):
        return FakeResponse(f"{PASSWORD_SUFFIX}:0\r\n")

    assert check_pwned("password", opener=fake_opener) == 0


def test_check_pwned_offline_returns_none():
    def fake_opener(request, timeout):
        raise urllib.error.URLError("no network")

    assert check_pwned("password", opener=fake_opener) is None


def test_load_common_passwords_ignores_comments_and_blanks(tmp_path):
    f = tmp_path / "words.txt"
    f.write_text("# comment\n\nHunter2\n  letmein  \n", encoding="utf-8")
    assert load_common_passwords(f) == {"hunter2", "letmein"}


def test_load_common_passwords_missing_file_uses_fallback(tmp_path):
    words = load_common_passwords(tmp_path / "does_not_exist.txt")
    assert "123456" in words


def test_shipped_wordlist_is_loaded():
    assert "123456" in COMMON_PASSWORDS
    assert len(COMMON_PASSWORDS) > 50


def test_common_password_check_is_case_insensitive():
    strength, _ = check_password("PassWord123")
    assert strength == "WEAK"


def test_common_password_is_weak():
    strength, suggestions = check_password("password")
    assert strength == "WEAK"
    assert suggestions


def test_short_simple_password_is_weak():
    strength, _ = check_password("abc")
    assert strength == "WEAK"


def test_medium_password():
    strength, _ = check_password("Zebra835")
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

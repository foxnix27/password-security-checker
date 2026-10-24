import argparse
import getpass
import hashlib
import re
import urllib.error
import urllib.request
from pathlib import Path

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"

COMMON_PASSWORDS_FILE = Path(__file__).with_name("common_passwords.txt")

# Used only if common_passwords.txt is missing.
FALLBACK_COMMON_PASSWORDS = {
    "123456", "12345678", "123456789", "password", "password1", "qwerty",
    "qwerty123", "abc123", "111111", "123123", "admin", "letmein",
}


def load_common_passwords(path=COMMON_PASSWORDS_FILE):
    """Load common passwords (one per line, lowercase) from a text file.

    Blank lines and lines starting with '#' are ignored.
    Falls back to a small built-in set if the file does not exist.
    """
    try:
        with open(path, encoding="utf-8") as f:
            return {
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith("#")
            }
    except FileNotFoundError:
        return set(FALLBACK_COMMON_PASSWORDS)


COMMON_PASSWORDS = load_common_passwords()

# Sequences that make a password easier to guess.
SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


def has_sequence(password, length=4):
    """Return True if the password contains a run like 'abcd', '1234' or 'qwer'
    (forwards or backwards)."""
    lowered = password.lower()
    for seq in SEQUENCES:
        for candidate in (seq, seq[::-1]):
            for i in range(len(candidate) - length + 1):
                if candidate[i:i + length] in lowered:
                    return True
    return False


def has_repeated_chars(password, count=3):
    """Return True if the same character appears `count` or more times in a row."""
    return re.search(r"(.)\1{%d,}" % (count - 1), password) is not None


def check_password(password):
    # Very common passwords are weak no matter how they score otherwise.
    if password.lower() in COMMON_PASSWORDS:
        return "WEAK", ["This is a very common password. Choose something unique."]

    score = 0
    suggestions = []

    # Check password length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 12 characters.")

    # Check for uppercase letters
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add at least one uppercase letter.")

    # Check for lowercase letters
    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add at least one lowercase letter.")

    # Check for numbers
    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Add at least one number.")

    # Check for special characters
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        suggestions.append("Add at least one special character.")

    # Penalise predictable patterns
    if has_repeated_chars(password):
        score -= 1
        suggestions.append("Avoid repeating the same character 3+ times in a row.")

    if has_sequence(password):
        score -= 1
        suggestions.append("Avoid sequences like 'abcd', '1234' or 'qwer'.")

    score = max(score, 0)

    # Determine strength
    if score <= 2:
        strength = "WEAK"
    elif score <= 4:
        strength = "MEDIUM"
    else:
        strength = "STRONG"

    return strength, suggestions


def check_pwned(password, timeout=5, opener=urllib.request.urlopen):
    """Check how many times a password appears in known data breaches.

    Uses the Have I Been Pwned range API with k-anonymity: only the first 5
    characters of the password's SHA-1 hash are sent, never the password
    itself or the full hash.

    Returns the number of times the password was seen (0 = not found),
    or None if the service could not be reached.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    request = urllib.request.Request(
        HIBP_RANGE_URL + prefix,
        headers={"User-Agent": "password-security-checker", "Add-Padding": "true"},
    )
    try:
        with opener(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, OSError):
        return None

    for line in body.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip().upper() == suffix:
            return int(count.strip() or 0)
    return 0


def main():
    parser = argparse.ArgumentParser(description="Check how strong a password is.")
    parser.add_argument(
        "--pwned",
        action="store_true",
        help="also check if the password appears in known data breaches "
        "(sends only a 5-character hash prefix to haveibeenpwned.com)",
    )
    args = parser.parse_args()

    print("=" * 40)
    print("       PASSWORD SECURITY CHECKER")
    print("=" * 40)

    password = getpass.getpass("Enter password: ")

    strength, suggestions = check_password(password)

    if args.pwned:
        count = check_pwned(password)
        if count is None:
            print("\nCould not reach the breach database (are you offline?).")
        elif count > 0:
            print(f"\nWARNING: this password appeared in {count:,} data breaches!")
            strength = "WEAK"
            suggestions.append("Never use this password again. Choose a new one.")
        else:
            print("\nGood news: this password was not found in known breaches.")

    print(f"\nPassword strength: {strength}")

    if suggestions:
        print("\nSuggestions:")
        for suggestion in suggestions:
            print(f"- {suggestion}")
    else:
        print("\nNo obvious weaknesses detected.")


if __name__ == "__main__":
    main()

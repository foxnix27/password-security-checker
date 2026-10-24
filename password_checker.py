import getpass
import re

# Small sample of very common passwords (extend this or load from a file).
COMMON_PASSWORDS = {
    "123456", "12345678", "123456789", "password", "password1", "qwerty",
    "qwerty123", "abc123", "111111", "123123", "admin", "letmein",
    "welcome", "iloveyou", "monkey", "dragon", "football", "sunshine",
}

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


def main():
    print("=" * 40)
    print("       PASSWORD SECURITY CHECKER")
    print("=" * 40)

    password = getpass.getpass("Enter password: ")

    strength, suggestions = check_password(password)

    print(f"\nPassword strength: {strength}")

    if suggestions:
        print("\nSuggestions:")
        for suggestion in suggestions:
            print(f"- {suggestion}")
    else:
        print("\nNo obvious weaknesses detected.")


if __name__ == "__main__":
    main()

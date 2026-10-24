import re
import getpass


def check_password(password):
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
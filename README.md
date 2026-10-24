# Password Security Checker

A simple command-line tool written in Python that evaluates the strength of a password and suggests how to improve it.

## Features

- Scores passwords on length, uppercase, lowercase, digits and special characters
- Detects very common passwords (e.g. `123456`, `password`)
- Detects repeated characters (`aaa`) and keyboard/alphabet/number sequences (`1234`, `abcd`, `qwer`)
- Gives clear suggestions to improve weak passwords
- Password input is hidden while typing (`getpass`) and is never stored or sent anywhere

## Usage

```bash
python password_checker.py
```

Example:

```
========================================
       PASSWORD SECURITY CHECKER
========================================
Enter password:

Password strength: MEDIUM

Suggestions:
- Use at least 12 characters.
- Add at least one special character.
```

## Running the tests

```bash
pip install pytest
pytest
```

## How the score works

| Check                          | Points |
| ------------------------------ | ------ |
| Length >= 12 / >= 8            | 2 / 1  |
| Uppercase letter               | 1      |
| Lowercase letter               | 1      |
| Digit                          | 1      |
| Special character              | 1      |
| Repeated characters (3+)       | -1     |
| Sequence (4+ chars)            | -1     |

Final rating: `WEAK` (0-2), `MEDIUM` (3-4), `STRONG` (5+). Passwords on the common-password list are always `WEAK`.

## Ideas for the future

- Load a larger common-password list from a file
- Entropy estimation
- Command-line arguments and a simple GUI

![Tests](https://github.com/foxnix27/password-security-checker/actions/workflows/tests.yml/badge.svg)
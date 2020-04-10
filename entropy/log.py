"""Miscellaneous logging functions."""

import sys


def info(msg: str) -> None:
    """Log a message to stderr.

    :param msg: message to print
    :type msg: str
    """
    green: str = "[\033[0;32m"
    reset: str = "\033[0m]"
    print(f"{green}*{reset} {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    """Log a warning to stderr.

    :param msg: message to print
    :type msg: str
    """
    yellow: str = "[\033[0;33m"
    reset: str = "\033[0m]"
    print(f"{yellow}*{reset} {msg}", file=sys.stderr)


def die(msg: str, error_code: int = 1) -> None:
    """Log an error to stderr and exit.

    :param msg: message to print
    :type msg: str
    :param error_code: error code to exit with, defaults to 1
    :type error_code: int
    """
    red: str = "[\033[0;31m"
    reset: str = "\033[0m]"
    print(f"{red}*{reset} {msg}", file=sys.stderr)
    sys.exit(error_code)

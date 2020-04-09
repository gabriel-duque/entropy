import sys


def info(msg: str) -> None:
    """Log a message to stderr."""
    green: str = "[\033[0;32m"
    reset: str = "\033[0m]"
    print(f"{green}*{reset} {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    """Log a warning to stderr."""
    yellow: str = "[\033[0;33m"
    reset: str = "\033[0m]"
    print(f"{yellow}*{reset} {msg}", file=sys.stderr)


def die(msg: str, errorcode: int = 1) -> None:
    """Log an error to stderr and exit."""
    red: str = "[\033[0;31m"
    reset: str = "\033[0m]"
    print(f"{red}*{reset} {msg}", file=sys.stderr)
    sys.exit(errorcode)

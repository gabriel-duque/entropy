#!/usr/bin/env python3

import argparse
import io

from typing import BinaryIO


def main() -> None:
    """ This is the function that gets called when `entropy` is run as an executable script and not imported as a lib.
    """
    parser: argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument("elf")
    args: argparse.Namespace = parser.parse_args()
    pf_x: int = (1 << 0)

    with open(args.elf, "rb") as f:
        byte_stream: BinaryIO = io.BytesIO(f.read())
    print(byte_stream)


if __name__ == "__main__":
    main()

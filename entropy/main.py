#!/usr/bin/env python3
"""
.. module:: entropy
   :platform: Unix, Windows, OSX
   :synopsis: a return-oriented programming chain searching tool for ELF x86_64 binaries implemented in Python3.

.. moduleauthor:: Gabriel Duque <gabriel.duque@lse.epita.fr>
"""

import argparse

from typing import List

from entropy import elf
from entropy import finder
from entropy import gadget
from entropy import log


def main() -> None:
    """ This is the function that gets called when ``entropy`` is run as an executable script and not imported as a lib.
    """
    parser: argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument("elf")
    args: argparse.Namespace = parser.parse_args()

    log.info(f"parsing file {args.elf}")
    input_elf: elf.ELF = elf.ELF.from_file_name(args.elf)
    gadget_finder: finder.Finder = finder.Finder(input_elf.raw)
    log.info(f"searching for gadgets")
    gadgets: List[gadget.Gadget] = gadget_finder(
        input_elf.iter_executable_segments()
    )
    log.info(f"found {len(gadgets)} gadgets")

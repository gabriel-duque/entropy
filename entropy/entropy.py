#!/usr/bin/env python3
"""
.. module:: entropy
   :platform: Unix, Windows, OSX
   :synopsis: a return-oriented programming chain searching tool for ELF x86_64 binaries implemented in Python3.

.. moduleauthor:: Gabriel Duque <gabriel.duque@lse.epita.fr>
"""

import argparse

import entropy.elf
import entropy.log


def main() -> None:
    """ This is the function that gets called when ``entropy`` is run as an executable script and not imported as a lib.
    """
    parser: argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument("elf")
    args: argparse.Namespace = parser.parse_args()

    entropy.log.info(f"parsing file {args.elf}")
    input_elf: entropy.elf.ELF = entropy.elf.ELF.from_file_name(args.elf)

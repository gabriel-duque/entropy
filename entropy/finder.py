"""Actual implementation of the return-oriented-programming chain searching."""

import functools
import operator

from typing import Iterator, List

import capstone

from entropy import elf
from entropy import gadget


class Finder:
    """Actual return-oriented programming gadget searching class."""

    __raw: bytearray

    def __init__(self, raw: bytearray) -> None:
        """Initialize our finder with the raw bytes of our file."""
        self.__raw: bytearray = raw

    def __call__(
        self, executable_segments: Iterator[elf.Phdr64LSB]
    ) -> List[gadget.Gadget]:
        """Search for gadgets in our segments and concatenate all
        returned lists.
        """
        return functools.reduce(
            operator.add, map(self.__find_gadgets, executable_segments)
        )

    def __find_gadgets(self, segment: elf.Phdr64LSB) -> List[gadget.Gadget]:
        """Search for gadgets in a specific segment."""
        return []

"""Representation of a return-oriented programming gadget."""

from typing import List, Tuple


class Gadget:
    """Representation of a return-oriented programming gadget."""

    vaddr: int
    instructions: List[Tuple[int, int, str, str]]

    def __init__(self, capstone_insn: List[Tuple[int, int, str, str]]) -> None:
        """Initialize our gadget representation."""

        self.vaddr = capstone_insn[0][0]
        self.instructions = capstone_insn

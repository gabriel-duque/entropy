"""Representation of a return-oriented programming gadget."""

from typing import Generator, List

import capstone


class Gadget:
    """Representation of a return-oriented programming gadget."""

    vaddr: int
    instructions: List[capstone.CsInsn]

    def __init__(
        self, vaddr: int, instructions: Generator[capstone.CsInsn, None, None]
    ) -> None:
        """Initialize our gadget representation."""

        self.vaddr = vaddr
        self.instructions = [instructions]

    def __str__(self):
        def instruction_to_str(instruction: capstone.CsInsn):
            instruction_str: str = instruction.mnemonic
            if instruction.op_str is not None:
                instruction_str += f" {instruction.op_str}"
            return instruction_str

        return f"{self.vaddr}: {' ; '.join(instruction_to_str(instruction) for instruction in self.instructions)}"

"""Representation of a return-oriented programming gadget."""

from typing import Generator, List

import capstone


class Gadget:
    """Representation of a return-oriented programming gadget."""

    vaddr: int
    instructions: List[capstone.CsInsn]

    def __init__(self, instructions: List[capstone.CsInsn]) -> None:
        """Initialize our gadget representation.

        :param instructions: list of ``capstone`` instructions in this gadget
        :type instructions: List[capstone.CsInsn]
        """

        self.vaddr = instructions[0].address
        self.instructions = instructions

    def __str__(self):
        """Get string representation of a gadget.

        :return: string representation of a gadget
        :rtype: str
        """

        def instruction_to_str(instruction: capstone.CsInsn):
            instruction_str: str = instruction.mnemonic
            if instruction.op_str is not None:
                instruction_str += f" {instruction.op_str}"
            return instruction_str

        return f"{hex(self.vaddr)}:\n\t" + "\n\t".join(
            instruction_to_str(instruction)
            for instruction in self.instructions
        )

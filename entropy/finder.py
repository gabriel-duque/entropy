"""Actual implementation of the return-oriented programming chain searching."""

import itertools

from typing import Generator, Iterator

import capstone
import capstone.x86_const

from entropy import elf
from entropy import gadget


class Finder:
    """Actual return-oriented programming gadget searching class."""

    __raw: bytes
    __arch: int
    __mode: int
    __md: capstone.Cs

    def __init__(self, raw: bytes) -> None:
        """Initialize our finder with the raw bytes of our file.

        :param raw: raw input file bytes
        :type raw: bytes
        """
        self.__raw: bytes = raw
        self.__arch: int = capstone.CS_ARCH_X86
        self.__mode: int = capstone.CS_MODE_64
        self.__md: capstone.Cs = capstone.Cs(self.__arch, self.__mode)
        self.__md.syntax = capstone.CS_OPT_SYNTAX_ATT
        self.__md.detail = True

    def __call__(
        self, executable_segments: Generator[elf.Phdr64LSB, None, None]
    ) -> Iterator[gadget.Gadget]:
        """Search for gadgets in our segments and concatenate all
        returned lists.

        :param executable_segments: generator iterating over executable segment program headers
        :type executable_segments: Generator[elf.Phdr64LSB, None, None]
        :return: iterator over found gadgets
        :rtype: Iterator[gadget.Gadget]
        """

        return itertools.chain(
            *(self.__find_gadgets(segment) for segment in executable_segments)
        )

    def __generate_gadgets(
        self, vaddr: int, instruction: capstone.CsInsn
    ) -> Generator[gadget.Gadget, None, None]:
        yield gadget.Gadget(vaddr, instruction)

    def __find_gadgets(
        self, segment: elf.Phdr64LSB
    ) -> Generator[gadget.Gadget, None, None]:
        """Search for gadgets in a specific segment.

        :param segment: program header of the analyzed segment
        :type segment: elf.Phdr64LSB
        :return: generator over gadgets found in segment
        :rtype: Generator[gadget.Gadget, None, None]
        """

        # This is arbitrary and stupid
        MAX_INSTRUCTION_SIZE: int = 15

        raw_segment: bytes = self.__raw[
            segment.p_offset : segment.p_offset + segment.p_filesz
        ]

        current: int
        for current in range(segment.p_filesz):
            offset: int = segment.p_offset + current
            vaddr: int = segment.p_vaddr + current

            try:
                instruction: capstone.CsInsn = next(
                    self.__md.disasm(
                        raw_segment[offset : offset + MAX_INSTRUCTION_SIZE],
                        vaddr,
                        1,  # Only disassemble *one* instruction
                    )
                )
            except StopIteration:
                continue

            if capstone.CS_GRP_RET in instruction.groups or (
                (
                    capstone.CS_GRP_JUMP in instruction.groups
                    or capstone.CS_GRP_CALL in instruction.groups
                )
                and all(
                    operand.type == capstone.x86_const.X86_OP_REG
                    for operand in instruction.operands
                )
            ):
                for current_gadget in self.__generate_gadgets(
                    vaddr, instruction
                ):
                    yield current_gadget

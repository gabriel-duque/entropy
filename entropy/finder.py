"""Actual implementation of the return-oriented programming chain searching."""

import itertools

from typing import Generator, Iterator, List

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
            *(self.find_gadgets(segment) for segment in executable_segments)
        )

    def __generate_gadgets(
        self, raw_segment: bytes, offset: int, vaddr: int, stem_size: int
    ) -> Generator[gadget.Gadget, None, None]:
        """Generate gadgets from a stem.

        :param raw_segment: raw bytes of the current segment
        :type raw_segment: bytes
        :param offset: offset of the stem in the current segment
        :type offset: int
        :param vaddr: virtual address of the stem in the current segment
        :type vaddr: int
        :return: generator over gadgets found starting at this stem
        :rtype: Generator[gadget.Gadget, None, None]
        """
        MAX_INSTRUCTION_SIZE: int = 15
        bad_address_count: int = 0
        end_offset: int = offset + stem_size
        end_vaddr: int = vaddr
        stem_groups: List[int] = [
            capstone.x86_const.X86_GRP_RET,
            capstone.x86_const.X86_GRP_JUMP,
            capstone.x86_const.X86_GRP_CALL,
            capstone.x86_const.X86_GRP_INT,
        ]

        while bad_address_count != MAX_INSTRUCTION_SIZE:
            instructions: List[capstone.CsInsn] = list(
                self.__md.disasm(raw_segment[offset:end_offset], vaddr)
            )

            if (
                sum(instruction.size for instruction in instructions)
                != end_offset - offset
                or instructions[-1].address != end_vaddr
                or any(
                    instruction_group in instruction.groups
                    for instruction_group in stem_groups
                    for instruction in instructions[:-1]
                )
            ):
                bad_address_count += 1
            else:
                bad_address_count = 0
                yield gadget.Gadget(instructions)

            offset -= 1
            vaddr -= 1

    def find_gadgets(
        self, segment: elf.Phdr64LSB
    ) -> Generator[gadget.Gadget, None, None]:
        """Search for gadgets in a specific segment.

        What we do is iterate over the whole segment byte by byte and
        disassemble *one* instruction each time. If the instruction could
        be the end of a gadget, we spread backwards from there and
        ``yield`` each valid gadget.

        In order to determine if an instruction could be the stem for a
        gadget list, we check it's ``capstone`` semantic instruction
        groups. If any of these conditions are verified, we consider this
        instruction to be a valid gadget ending:

        * is in the ``CS_GRP_RET`` ``capstone`` group
        * is in the ``CS_GRP_JMP`` ``capstone`` group and operand is a register
        * is in the ``CS_GRP_CALL`` ``capstone`` group and operand is a register

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
            vaddr: int = segment.p_vaddr + current

            try:
                instruction: capstone.CsInsn = next(
                    self.__md.disasm(
                        raw_segment[current : current + MAX_INSTRUCTION_SIZE],
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
                    raw_segment, current, vaddr, instruction.size
                ):
                    yield current_gadget

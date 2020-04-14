"""Actual implementation of the return-oriented programming chain searching."""

import itertools
import re

from typing import Generator, Iterator, List, Tuple

import capstone
import capstone.x86_const

capstone.x86_const.X86_REG_ENDING

from entropy import elf
from entropy import gadget
from entropy import log


class Finder:
    """Actual return-oriented programming gadget searching class."""

    __raw: bytes
    __arch: int
    __mode: int
    __md: capstone.Cs
    __gadget_stems: Iterator[Tuple[bytes, int]]

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
        self.__gadget_stems = itertools.chain(
            self.__rop_stems(), self.__jop_stems(), self.__syscall_stems()
        )

    def __rop_stems(self) -> Iterator[Tuple[bytes, int]]:
        if not (
            self.__arch == capstone.CS_ARCH_X86
            and self.__mode == capstone.CS_MODE_64
        ):
            log.die("unsupported architecture or mode")
        else:
            return iter(
                [
                    (b"\xc3", 1),  # ret
                    (b"\xc2[\x00-\xff]{2}", 3),  # ret <imm>
                    (b"\xcb", 1),  # retf
                    (b"\xca[\x00-\xff]{2}", 3),  # retf <imm>
                    # MPX
                    (b"\xf2\xc3", 2),  # ret
                    (b"\xf2\xc2[\x00-\xff]{2}", 4),  # ret <imm>
                ]
            )

    def __jop_stems(self) -> Iterator[Tuple[bytes, int]]:
        if not (
            self.__arch == capstone.CS_ARCH_X86
            and self.__mode == capstone.CS_MODE_64
        ):
            log.die("unsupported architecture or mode")
        else:
            gadgets: List[Tuple[bytes, int]] = [
                # Jump gadget stems
                # call/jmp reg
                # d0-d7=call,e0-e7=jmp
                # x64: 0=rax,1=rcx,2=rdx,3=rbx,4=rsp,5=rbp,6=rsi,7=rdi
                (b"\xff[\xd0-\xd7\xe0-\xe7]", 2),
                # call/jmp (reg)
                # 10-17=call,20-27=jmp
                # x64: 0=rax,1=rcx,2=rdx,3=rbx,            6=rsi,7=rdi
                (b"\xff[\x10-\x13\x16-\x17\x20-\x23\x26-\x27]", 2),
                # call/jmp (reg)
                # 14=call,24=jmp
                # x64: rsp
                (b"\xff[\x14\x24]\x24", 3),
                # call/jmp (reg + offset), -0x80 <= offset <= 0x7f
                # 50-57=call,60-67=jmp
                # x64: 0=rax,1=rcx,2=rdx,3=rbx,      5=rbp,6=rsi,7=rdi
                (b"\xff[\x50-\x53\x55-\x57\x60-\x63\x65-\x67][\x00-\xff]", 3),
                # call/jmp (reg + offset), -0x80 <= offset <= 0x7f
                # 54=call,64=jmp
                # x64: rsp
                (b"\xff[\x54\x64]\x24[\x00-\xff]", 4),
                # call/jmp (reg + offset), -0x80000000 <= offset <= 0x7fffffff
                # 90-97=call,a0-a7=jmp
                # x64: 0=rax,1=rcx,2=rdx,3=rbx,      5=rbp,6=rsi,7=rdi
                (
                    b"\xff[\x90-\x93\x95-\x97\xa0-\xa3\xa5-\xa7][\x00-\xff]{4}",
                    6,
                ),
                # call/jmp (reg + offset), -0x80000000 <= offset <= 0x7fffffff
                # 94=call,a4=jmp
                # x64: rsp
                (b"\xff[\x94\xa4]\x24[\x00-\xff]{4}", 7),
            ]
            # in x64, by adding 0x41 before a sequence with
            # 0=rax,1=rcx,2=rdx,3=rbx,4=rsp,5=rbp,6=rsi,7=rdi
            # we convert it to the same sequence with
            # 0= r8,1= r9,2=r10,3=r11,4=r12,5=r13,6=r14,7=r15
            gadgets.extend(
                list((b"\x41" + op, size + 1) for (op, size) in gadgets)
            )
            # finally, add extra sequences common to x86 and x64
            gadgets.extend(
                [
                    (b"\xeb[\x00-\xff]", 2),  # jmp offset
                    (b"\xe9[\x00-\xff]{4}", 5),  # jmp offset
                    # MPX
                    (
                        b"\xf2\xff[\x20\x21\x22\x23\x26\x27]{1}",
                        3,
                    ),  # jmp  [reg]
                    (
                        b"\xf2\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}",
                        3,
                    ),  # jmp  [reg]
                    (
                        b"\xf2\xff[\x10\x11\x12\x13\x16\x17]{1}",
                        3,
                    ),  # jmp  [reg]
                    (
                        b"\xf2\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}",
                        3,
                    ),  # call [reg]
                ]
            )
            return iter(gadgets)

    def __syscall_stems(self) -> Iterator[Tuple[bytes, int]]:
        if not (
            self.__arch == capstone.CS_ARCH_X86
            and self.__mode == capstone.CS_MODE_64
        ):
            log.die("unsupported architecture or mode")
        else:
            return iter(
                [
                    (b"\xcd\x80", 2),  # int 0x80
                    (b"\x0f\x34", 2),  # sysenter
                    (b"\x0f\x05", 2),  # syscall
                    (b"\xcd\x80\xc3", 3),  # int 0x80 ; ret
                    (b"\x0f\x34\xc3", 3),  # sysenter ; ret
                    (b"\x0f\x05\xc3", 3),  # syscall ; ret
                    (
                        b"\x65\xff\x15\x10\x00\x00\x00",
                        7,
                    ),  # call DWORD PTR gs:0x10
                    (
                        b"\x65\xff\x15\x10\x00\x00\x00\xc3",
                        8,
                    ),  # call DWORD PTR gs:0x10 ; ret
                ]
            )

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
        MAX_INSTR_SIZE: int = 100
        gadget_ends: List[str] = [
            "ret",
            "retf",
            "int1",
            "int2",
            "int3",
            "sysenter",
            "jmp",
            "call",
            "syscall",
        ]

        raw_segment: bytes = self.__raw[
            segment.p_offset : segment.p_offset + segment.p_filesz
        ]

        for stem_bytes, stem_size in self.__gadget_stems:
            for match in re.finditer(stem_bytes, raw_segment):
                end: int = match.start() + stem_size
                for i in range(MAX_INSTR_SIZE):
                    start: int = match.start() - i
                    opcodes: bytes = raw_segment[start:end]
                    disassembled: List[Tuple[int, int, str, str]] = list(
                        self.__md.disasm_lite(opcodes, segment.p_vaddr + start)
                    )
                    if (
                        sum(size for _, size, _, _ in disassembled)
                        != i + stem_size
                        or not any(
                            disassembled[-1][2].startswith(g_end)
                            for g_end in gadget_ends
                        )
                        or any(
                            mnemonic.startswith(g_end)
                            for g_end in gadget_ends
                            for _, _, mnemonic, _ in disassembled[:-1]
                        )
                    ):
                        # We've read less instructions than planned so something went wrong in Capstone
                        continue
                    yield gadget.Gadget(disassembled)

"""Simple representation of the executable and linkable format (ELF)."""

import ctypes
import os
import sys

from typing import Generator, List, Tuple, Type, Union

from entropy import log


class EhdrIdentIndex:
    """ELF header identification indices."""

    EI_CLASS = 0x04
    EI_DATA = 0x05


class EhdrIdentValue:
    """ELF header identification values."""

    ELFCLASS64 = 0x02
    ELFDATA2LSB = 0x01
    EM_X86_64 = 0x3E


class Ehdr64LSB(ctypes.LittleEndianStructure):
    """64 bit little endian ELF header."""

    EI_NINDENT: int = 16

    _fields_: List[
        Tuple[
            str,
            Union[
                Type[ctypes.Array],
                Type[ctypes.c_uint16],
                Type[ctypes.c_uint32],
                Type[ctypes.c_uint64],
            ],
        ]
    ] = [
        ("e_ident", EI_NINDENT * ctypes.c_ubyte),
        ("e_type", ctypes.c_uint16),
        ("e_machine", ctypes.c_uint16),
        ("e_version", ctypes.c_uint32),
        ("e_entry", ctypes.c_uint64),
        ("e_phoff", ctypes.c_uint64),
        ("e_shoff", ctypes.c_uint64),
        ("e_flags", ctypes.c_uint32),
        ("e_ehsize", ctypes.c_uint16),
        ("e_phentsize", ctypes.c_uint16),
        ("e_phnum", ctypes.c_uint16),
        ("e_shentsize", ctypes.c_uint16),
        ("e_shnum", ctypes.c_uint16),
        ("e_shstrndx", ctypes.c_uint16),
    ]


class Phdr64LSB(ctypes.LittleEndianStructure):
    """64 bit little endian ELF program header."""

    _fields_: List[
        Tuple[str, Union[Type[ctypes.c_uint32], Type[ctypes.c_uint64]]]
    ] = [
        ("p_type", ctypes.c_uint32),
        ("p_flags", ctypes.c_uint32),
        ("p_offset", ctypes.c_uint64),
        ("p_vaddr", ctypes.c_uint64),
        ("p_paddr", ctypes.c_uint64),
        ("p_filesz", ctypes.c_uint64),
        ("p_memsz", ctypes.c_uint64),
        ("p_align", ctypes.c_uint64),
    ]

    @property
    def is_executable(self) -> bool:
        """Check if this segment will be loaded with executable permissions."""
        PT_LOAD: ctypes.c_uint32 = ctypes.c_uint32(1)
        PF_X: ctypes.c_uint32 = ctypes.c_uint32(1)
        return self.p_type == PT_LOAD.value and (self.p_flags & PF_X.value)


class ELF:
    """Simple representation of an ELF file."""

    raw: bytes
    ehdr: Ehdr64LSB
    phdr_list: List[Phdr64LSB]

    def __init__(self, raw: bytes) -> None:
        """Build a new ELF object from bytes.

        :param raw: raw bytes of the ELF file
        :type raw: bytes
        """
        self.raw = bytes(raw)
        try:
            self.ehdr = Ehdr64LSB.from_buffer_copy(self.raw)
        except ValueError as e:
            log.die(
                "raw buffer was not large enough to carry a valid ELF header"
            )

        if (
            self.ehdr.e_ident[EhdrIdentIndex.EI_CLASS]
            != EhdrIdentValue.ELFCLASS64
        ):
            log.die(
                f"unsupported ELF class: {self.ehdr.e_ident[EhdrIdentIndex.EI_CLASS]}"
            )

        if (
            self.ehdr.e_ident[EhdrIdentIndex.EI_DATA]
            != EhdrIdentValue.ELFDATA2LSB
        ):
            log.die(
                f"unsupported ELF data encoding: {self.ehdr.e_ident[EhdrIdentIndex.EI_DATA]}"
            )

        if self.ehdr.e_machine != EhdrIdentValue.EM_X86_64:
            log.die(f"unsupported machine architecture: {self.ehdr.e_machine}")

        try:
            self.phdr_list = list(
                Phdr64LSB.from_buffer_copy(
                    self.raw, self.ehdr.e_phoff + i * self.ehdr.e_phentsize
                )
                for i in range(self.ehdr.e_phnum)
            )
        except ValueError as e:
            log.die(
                "raw buffer was not large enough to carry all ELF program headers"
            )

    def gen_executable_segments(self) -> Generator[Phdr64LSB, None, None]:
        """Return a generator iterating over executable segment program headers only.

        A segment will be considered as executable if it's type is
        ``PT_LOAD`` and it will be loaded with the ``PF_X`` ``p_flag``.

        :return: a generator iterating over executable segment program headers
        :rtype: Generator[Phdr64LSB, None, None]
        """
        return (phdr for phdr in self.phdr_list if phdr.is_executable)

    @classmethod
    def from_file_name(cls: type, file_name: str):
        """Create an ELF object from a file name.

        :param cls: class of which we want to return an instance (ELF here)
        :type cls: type
        :param file_name: file we wish to create and ELF object from
        :type file_name: str
        """
        try:
            with open(file_name, "rb") as f:
                return cls(f.read())
        except OSError as e:
            log.die(f"{os.path.basename(sys.argv[0])}: {e.strerror}")

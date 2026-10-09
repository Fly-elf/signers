from enum import Enum, Flag, FlagBoundary

__all__ = ["PreserveMetadata", "SignatureSlot", "SigningFlags", "Strict", "Timestamp"]


class SigningFlags(Flag, boundary=FlagBoundary.KEEP):
    HOST = 0x0001
    HARD = 0x0100
    KILL = 0x0200
    EXPIRES = 0x0400
    LIBRARY = 0x2000
    RUNTIME = 0x1_0000
    LINKER_SIGNED = 0x2_0000


class PreserveMetadata(Flag):
    IDENTIFIER = 1 << 0
    ENTITLEMENTS = 1 << 1
    REQUIREMENTS = 1 << 2
    FLAGS = 1 << 3
    RUNTIME = 1 << 4
    LAUNCH_CONSTRAINTS = 1 << 5
    LIBRARY_CONSTRAINTS = 1 << 6


class Timestamp(Enum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class Strict(Enum):
    ALL = "ALL"
    SYMLINKS = "SYMLINKS"
    SIDEBAND = "SIDEBAND"


class SignatureSlot(Enum):
    FIRST = "FIRST"
    SECOND = "SECOND"

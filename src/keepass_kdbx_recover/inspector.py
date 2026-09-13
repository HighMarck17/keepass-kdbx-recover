"""KDBX header inspector.

Reads the plaintext header of a .kdbx file and reports the format version, the
cipher, and - most importantly - the key derivation function (KDF) and its
parameters. The KDF decides whether a GPU (hashcat) is worth using:

    AES-KDF  is iterated AES, compute-bound  -> a GPU gives a BIG advantage.
    Argon2   is memory-hard by design        -> a GPU gives LITTLE advantage.

No password or secret is read; only the public header is parsed.
"""

import struct
from dataclasses import dataclass
from enum import StrEnum
from os import PathLike

MAGIC1 = 0x9AA2D903
MAGIC2 = 0xB54BFB67

KDF_UUIDS = {
    bytes([0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60,
           0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA]): "AES-KDF",
    bytes([0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B,
           0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C]): "Argon2d",
    bytes([0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73,
           0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6]): "Argon2id",
}
CIPHER_UUIDS = {
    bytes([0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50,
           0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF]): "AES-256",
    bytes([0xAD, 0x68, 0xF2, 0x9F, 0x57, 0x6F, 0x4B, 0xB9,
           0xA3, 0x6A, 0xD4, 0x7A, 0xF9, 0x65, 0x34, 0x6C]): "ChaCha20",
    bytes([0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5,
           0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A]): "TwoFish",
}


class GpuAdvice(StrEnum):
    BIG_ADVANTAGE = "big"
    LITTLE_ADVANTAGE = "little"
    UNKNOWN = "unknown"


@dataclass
class Inspection:
    major: int
    minor: int
    cipher: str
    kdf: str
    kdf_params: dict[str, int]
    gpu_advice: GpuAdvice

    @property
    def version(self) -> str:
        return f"{self.major}.{self.minor}"


def parse_variant_dict(data: bytes) -> dict[str, object]:
    """Parse a KDBX4 VariantDictionary (used for the KDF parameter block)."""
    out: dict[str, object] = {}
    pos = 2  # skip the 2-byte version
    while pos < len(data):
        vtype = data[pos]
        pos += 1
        if vtype == 0x00:
            break
        klen = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        key = data[pos : pos + klen].decode("utf-8")
        pos += klen
        vlen = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        raw = data[pos : pos + vlen]
        pos += vlen
        if vtype == 0x04:
            out[key] = struct.unpack("<I", raw)[0]
        elif vtype == 0x05:
            out[key] = struct.unpack("<Q", raw)[0]
        elif vtype == 0x08:
            out[key] = bool(raw[0])
        elif vtype == 0x0C:
            out[key] = struct.unpack("<i", raw)[0]
        elif vtype == 0x0D:
            out[key] = struct.unpack("<q", raw)[0]
        elif vtype == 0x18:
            out[key] = raw.decode("utf-8")
        else:
            out[key] = raw  # byte[]
    return out


def parse_header(blob: bytes) -> Inspection:
    """Parse a KDBX header from raw bytes. Raises ValueError if it is not KDBX."""
    if len(blob) < 12:
        raise ValueError("File is too small to be a KDBX database.")
    sig1, sig2 = struct.unpack_from("<II", blob, 0)
    if sig1 != MAGIC1 or sig2 != MAGIC2:
        raise ValueError("This does not look like a valid KDBX file.")

    minor, major = struct.unpack_from("<HH", blob, 8)

    pos = 12
    size_fmt = "<I" if major >= 4 else "<H"
    size_len = 4 if major >= 4 else 2
    cipher_raw: bytes | None = None
    kdf_dict: dict[str, object] | None = None
    rounds_kdbx3: int | None = None
    ended = False

    try:
        while pos < len(blob):
            fid = blob[pos]
            pos += 1
            if pos + size_len > len(blob):
                raise ValueError("Truncated KDBX header (field length is cut off).")
            flen = struct.unpack_from(size_fmt, blob, pos)[0]
            pos += size_len
            if pos + flen > len(blob):
                raise ValueError("Truncated KDBX header (field data is cut off).")
            fdata = blob[pos : pos + flen]
            pos += flen
            if fid == 0:  # end of header
                ended = True
                break
            if fid == 2:  # CipherID
                cipher_raw = fdata
            elif fid == 6 and major < 4:  # TransformRounds (KDBX3 AES-KDF)
                rounds_kdbx3 = struct.unpack("<Q", fdata)[0]
            elif fid == 11 and major >= 4:  # KDF parameters
                kdf_dict = parse_variant_dict(fdata)
    except (struct.error, IndexError, UnicodeDecodeError) as exc:
        raise ValueError(f"Malformed KDBX header: {exc}") from exc

    if not ended:
        raise ValueError("KDBX header is incomplete or truncated (no end-of-header marker).")

    cipher = CIPHER_UUIDS.get(cipher_raw, cipher_raw.hex()) if cipher_raw else "unknown"

    if kdf_dict is None:
        # KDBX 3.x always uses AES-KDF.
        params = {"rounds": rounds_kdbx3} if rounds_kdbx3 is not None else {}
        return Inspection(major, minor, cipher, "AES-KDF", params, GpuAdvice.BIG_ADVANTAGE)

    uuid = kdf_dict.get("$UUID", b"")
    kdf_name = KDF_UUIDS.get(uuid, uuid.hex() if isinstance(uuid, bytes) else str(uuid))
    if kdf_name == "AES-KDF":
        params = {"rounds": int(kdf_dict.get("R", 0))}
        advice = GpuAdvice.BIG_ADVANTAGE
    elif kdf_name.startswith("Argon2"):
        params = {
            "memory": int(kdf_dict.get("M", 0)),
            "iterations": int(kdf_dict.get("I", 0)),
            "parallelism": int(kdf_dict.get("P", 0)),
        }
        advice = GpuAdvice.LITTLE_ADVANTAGE
    else:
        params = {}
        advice = GpuAdvice.UNKNOWN

    return Inspection(major, minor, cipher, kdf_name, params, advice)


# The outer KDBX header is small in practice; this cap is far above any real
# header yet guards against reading a huge database body into memory.
_MAX_HEADER_READ = 1_048_576  # 1 MiB


def inspect_file(path: str | PathLike[str]) -> Inspection:
    """Read and inspect the header of a .kdbx file on disk."""
    with open(path, "rb") as handle:
        blob = handle.read(_MAX_HEADER_READ)
    return parse_header(blob)


def format_inspection(insp: Inspection) -> str:
    """Render a human-readable inspection report (ASCII)."""
    lines = [
        f"KDBX format : {insp.version}",
        f"Cipher      : {insp.cipher}",
        f"KDF         : {insp.kdf}",
    ]
    if insp.kdf == "AES-KDF":
        rounds = insp.kdf_params.get("rounds")
        if rounds:
            lines.append(f"  rounds    : {rounds:,}")
        lines.append("  => AES-KDF is compute-bound: a GPU (hashcat) gives a BIG advantage.")
    elif insp.kdf.startswith("Argon2"):
        mem = insp.kdf_params.get("memory", 0)
        lines.append(f"  memory    : {mem:,} bytes (~{mem / 1024 / 1024:.0f} MiB)")
        lines.append(f"  iterations: {insp.kdf_params.get('iterations')}")
        lines.append(f"  parallel. : {insp.kdf_params.get('parallelism')}")
        lines.append("  => Argon2 is memory-hard: a GPU gives LITTLE advantage; use CPU here.")
    return "\n".join(lines)

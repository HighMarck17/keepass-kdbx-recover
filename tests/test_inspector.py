"""Tests for the KDBX header inspector, using crafted byte fixtures."""

import struct

import pytest

from keepass_kdbx_recover.inspector import (
    GpuAdvice,
    Inspection,
    inspect_file,
    parse_header,
    parse_variant_dict,
)

SIG = struct.pack("<II", 0x9AA2D903, 0xB54BFB67)
AES_CIPHER = bytes([0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50,
                    0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF])
CHACHA_CIPHER = bytes([0xAD, 0x68, 0xF2, 0x9F, 0x57, 0x6F, 0x4B, 0xB9,
                       0xA3, 0x6A, 0xD4, 0x7A, 0xF9, 0x65, 0x34, 0x6C])
AESKDF_UUID = bytes([0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60,
                     0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA])
ARGON2ID_UUID = bytes([0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73,
                       0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6])


def _field3(fid, data):
    return bytes([fid]) + struct.pack("<H", len(data)) + data


def _field4(fid, data):
    return bytes([fid]) + struct.pack("<I", len(data)) + data


def _vd_entry(vtype, key, val):
    kb = key.encode()
    return bytes([vtype]) + struct.pack("<I", len(kb)) + kb + struct.pack("<I", len(val)) + val


def kdbx3_aeskdf():
    b = SIG + struct.pack("<HH", 1, 3)  # minor=1, major=3
    b += _field3(2, AES_CIPHER)
    b += _field3(6, struct.pack("<Q", 60000))  # transform rounds
    b += _field3(0, b"")
    return b


def kdbx4_argon2id():
    b = SIG + struct.pack("<HH", 0, 4)  # minor=0, major=4
    b += _field4(2, CHACHA_CIPHER)
    vd = struct.pack("<H", 0x0100)
    vd += _vd_entry(0x42, "$UUID", ARGON2ID_UUID)
    vd += _vd_entry(0x05, "M", struct.pack("<Q", 67108864))  # 64 MiB
    vd += _vd_entry(0x05, "I", struct.pack("<Q", 10))
    vd += _vd_entry(0x04, "P", struct.pack("<I", 4))
    vd += bytes([0x00])
    b += _field4(11, vd)
    b += _field4(0, b"")
    return b


def kdbx4_aeskdf():
    b = SIG + struct.pack("<HH", 0, 4)
    b += _field4(2, AES_CIPHER)
    vd = struct.pack("<H", 0x0100)
    vd += _vd_entry(0x42, "$UUID", AESKDF_UUID)
    vd += _vd_entry(0x05, "R", struct.pack("<Q", 100000))
    vd += bytes([0x00])
    b += _field4(11, vd)
    b += _field4(0, b"")
    return b


def test_parse_kdbx3_reports_aeskdf_and_big_gpu_advantage():
    insp = parse_header(kdbx3_aeskdf())
    assert isinstance(insp, Inspection)
    assert insp.version == "3.1"
    assert insp.cipher == "AES-256"
    assert insp.kdf == "AES-KDF"
    assert insp.kdf_params["rounds"] == 60000
    assert insp.gpu_advice is GpuAdvice.BIG_ADVANTAGE


def test_parse_kdbx4_argon2id_reports_little_gpu_advantage():
    insp = parse_header(kdbx4_argon2id())
    assert insp.version == "4.0"
    assert insp.cipher == "ChaCha20"
    assert insp.kdf == "Argon2id"
    assert insp.kdf_params == {"memory": 67108864, "iterations": 10, "parallelism": 4}
    assert insp.gpu_advice is GpuAdvice.LITTLE_ADVANTAGE


def test_parse_kdbx4_aeskdf_reports_rounds_and_big_advantage():
    insp = parse_header(kdbx4_aeskdf())
    assert insp.kdf == "AES-KDF"
    assert insp.kdf_params["rounds"] == 100000
    assert insp.gpu_advice is GpuAdvice.BIG_ADVANTAGE


def test_parse_header_rejects_non_kdbx():
    with pytest.raises(ValueError):
        parse_header(b"not a kdbx file at all")


def test_parse_variant_dict_decodes_every_value_type():
    vd = struct.pack("<H", 0x0100)
    vd += _vd_entry(0x04, "u32", struct.pack("<I", 7))
    vd += _vd_entry(0x05, "u64", struct.pack("<Q", 8))
    vd += _vd_entry(0x08, "flag", bytes([1]))
    vd += _vd_entry(0x0C, "i32", struct.pack("<i", -3))
    vd += _vd_entry(0x0D, "i64", struct.pack("<q", -9))
    vd += _vd_entry(0x18, "text", b"hi")
    vd += bytes([0x00])
    out = parse_variant_dict(vd)
    assert out["u32"] == 7
    assert out["u64"] == 8
    assert out["flag"] is True
    assert out["i32"] == -3
    assert out["i64"] == -9
    assert out["text"] == "hi"


def test_inspect_file_reads_from_disk(tmp_path):
    p = tmp_path / "sample.kdbx"
    p.write_bytes(kdbx4_argon2id())
    insp = inspect_file(p)
    assert insp.kdf == "Argon2id"


def test_parse_header_raises_on_truncated_field():
    # Valid signature + version, then a cipher field claiming 16 bytes but only 2.
    blob = SIG + struct.pack("<HH", 0, 4) + bytes([2]) + struct.pack("<I", 16) + b"\x00\x00"
    with pytest.raises(ValueError):
        parse_header(blob)


def test_parse_header_raises_when_end_of_header_missing():
    # A complete cipher field but no end-of-header (fid 0) marker: must not be
    # silently treated as AES-KDF.
    blob = SIG + struct.pack("<HH", 0, 4) + _field4(2, CHACHA_CIPHER)
    with pytest.raises(ValueError):
        parse_header(blob)


def test_inspect_reads_header_beyond_4096_bytes(tmp_path):
    # A large public-custom-data field (id 12) pushes the KDF block past 4096 bytes.
    vd = struct.pack("<H", 0x0100)
    vd += _vd_entry(0x42, "$UUID", ARGON2ID_UUID)
    vd += _vd_entry(0x05, "M", struct.pack("<Q", 67108864))
    vd += _vd_entry(0x05, "I", struct.pack("<Q", 10))
    vd += _vd_entry(0x04, "P", struct.pack("<I", 4))
    vd += bytes([0x00])
    blob = SIG + struct.pack("<HH", 0, 4)
    blob += _field4(12, b"\x00" * 5000)  # bigger than a 4096-byte read
    blob += _field4(11, vd)
    blob += _field4(0, b"")
    p = tmp_path / "big.kdbx"
    p.write_bytes(blob)
    insp = inspect_file(p)
    assert insp.kdf == "Argon2id"  # must not be misreported as AES-KDF

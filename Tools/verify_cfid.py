#!/usr/bin/env python3
"""
verify_cfid.py — Parse a raw Matter TLV RCAC and compute the CompressedFabricID.

Usage:
  python3 verify_cfid.py "<hex string from [RCAC-DEBUG] output>" <fabricID-hex>

Example:
  python3 verify_cfid.py "15 30 01 01 00 ..." 00000000F48338FE

What this does:
  1. Parses the raw RCAC TLV to extract the public key bytes (context tag 9)
  2. Extracts the X coordinate (skipping the 0x04 uncompressed prefix if present)
  3. Computes CFID = HKDF-SHA256(IKM=X, salt=BE8(fabricID), info="CompressedFabric", len=8)
  4. Prints the result alongside the expected value from homed logs
"""

import sys
import struct
import hmac
import hashlib


# ──────────────────────────────────────────────────────────────────────────────
# Minimal Matter TLV parser (just enough to extract the public key)
# ──────────────────────────────────────────────────────────────────────────────

def parse_tlv(data: bytes, offset: int = 0):
    """
    Parse a single TLV element starting at `offset`.
    Returns (tag, value, next_offset) where:
      - tag is (tag_form, tag_value) or None for anonymous
      - value is the decoded value (bytes for octet strings, dict for structures, int for ints)
      - next_offset is where the next element starts
    """
    if offset >= len(data):
        return None, None, offset

    control = data[offset]
    offset += 1

    element_type = control & 0x1F
    tag_form = control & 0xE0

    # End-of-container
    if element_type == 0x18:
        return "END", None, offset

    # Decode tag
    tag = None
    if tag_form == 0x00:     # anonymous
        tag = None
    elif tag_form == 0x20:   # context-specific (1-byte tag)
        tag = data[offset]
        offset += 1
    elif tag_form == 0x40:   # common profile (2-byte)
        tag = struct.unpack_from("<H", data, offset)[0]
        offset += 2
    else:
        raise ValueError(f"Unsupported tag form 0x{tag_form:02X} at offset {offset-1}")

    # Decode value
    value = None
    if element_type in (0x00,):    # 1-byte signed int
        value = struct.unpack_from("b", data, offset)[0]; offset += 1
    elif element_type == 0x01:     # 2-byte signed
        value = struct.unpack_from("<h", data, offset)[0]; offset += 2
    elif element_type == 0x02:     # 4-byte signed
        value = struct.unpack_from("<i", data, offset)[0]; offset += 4
    elif element_type == 0x03:     # 8-byte signed
        value = struct.unpack_from("<q", data, offset)[0]; offset += 8
    elif element_type == 0x04:     # 1-byte unsigned
        value = data[offset]; offset += 1
    elif element_type == 0x05:     # 2-byte unsigned
        value = struct.unpack_from("<H", data, offset)[0]; offset += 2
    elif element_type == 0x06:     # 4-byte unsigned
        value = struct.unpack_from("<I", data, offset)[0]; offset += 4
    elif element_type == 0x07:     # 8-byte unsigned
        value = struct.unpack_from("<Q", data, offset)[0]; offset += 8
    elif element_type == 0x08:     # bool false
        value = False
    elif element_type == 0x09:     # bool true
        value = True
    elif element_type in (0x10, 0x11, 0x12):   # octet string (1/2/4-byte length)
        len_bytes = {0x10: 1, 0x11: 2, 0x12: 4}[element_type]
        if len_bytes == 1:
            length = data[offset]
        elif len_bytes == 2:
            length = struct.unpack_from("<H", data, offset)[0]
        else:
            length = struct.unpack_from("<I", data, offset)[0]
        offset += len_bytes
        value = bytes(data[offset:offset+length])
        offset += length
    elif element_type in (0x0C, 0x0D, 0x0E):   # utf-8 string
        len_bytes = {0x0C: 1, 0x0D: 2, 0x0E: 4}[element_type]
        if len_bytes == 1:
            length = data[offset]
        elif len_bytes == 2:
            length = struct.unpack_from("<H", data, offset)[0]
        else:
            length = struct.unpack_from("<I", data, offset)[0]
        offset += len_bytes
        value = data[offset:offset+length].decode("utf-8", errors="replace")
        offset += length
    elif element_type == 0x14:    # null
        value = None
    elif element_type in (0x15, 0x16, 0x17):   # structure / array / list
        fields = {}
        elements = []
        while offset < len(data):
            child_tag, child_value, offset = parse_tlv(data, offset)
            if child_tag == "END":
                break
            if child_tag is not None:
                fields[child_tag] = child_value
            else:
                elements.append(child_value)
        value = fields if element_type == 0x15 else elements
    else:
        raise ValueError(f"Unknown element type 0x{element_type:02X}")

    return tag, value, offset


def extract_public_key(rcac_bytes: bytes) -> bytes:
    """Extract the EC public key bytes from a Matter TLV RCAC (context tag 9)."""
    tag, structure, _ = parse_tlv(rcac_bytes, 0)
    if not isinstance(structure, dict):
        raise ValueError(f"Expected TLV structure at root, got: {type(structure)}")

    if 9 not in structure:
        print(f"  Available tags: {sorted(structure.keys())}")
        raise ValueError("Context tag 9 (publicKey) not found in RCAC structure")

    return structure[9]


def extract_fabric_id_from_noc_subject(structure: dict) -> int:
    """Extract fabricID from a subject DN (list at tag 6)."""
    # The subject is a list/structure at tag 6
    # DN attributes: fabricID is at tag 21
    subject = structure.get(6, {})
    if isinstance(subject, dict) and 21 in subject:
        return subject[21]
    if isinstance(subject, list):
        # Try to find by parsing as fields
        pass
    return None


# ──────────────────────────────────────────────────────────────────────────────
# HKDF-SHA256 (pure Python, RFC 5869)
# ──────────────────────────────────────────────────────────────────────────────

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF with SHA-256."""
    # Extract
    if not salt:
        salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # Expand
    output = b""
    t = b""
    counter = 1
    while len(output) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output += t
        counter += 1
    return output[:length]


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        print("\nUsage: python3 verify_cfid.py '<hex bytes>' <fabricID-hex>")
        sys.exit(1)

    # Parse hex input (spaces or no spaces)
    hex_str = sys.argv[1].replace(" ", "").replace(":", "")
    rcac_bytes = bytes.fromhex(hex_str)
    fabric_id_hex = sys.argv[2].replace("0x", "").replace("0X", "")
    fabric_id = int(fabric_id_hex, 16)

    print(f"RCAC TLV: {len(rcac_bytes)} bytes")
    print(f"FabricID: 0x{fabric_id:016X} ({fabric_id})")
    print()

    # Parse RCAC
    tag, structure, _ = parse_tlv(rcac_bytes, 0)
    print(f"Top-level tag: {tag}, type: {type(structure).__name__}")
    if isinstance(structure, dict):
        print(f"  Context tags present: {sorted(structure.keys())}")
    print()

    # Extract public key
    pub_key = extract_public_key(rcac_bytes)
    print(f"Public key from TLV ({len(pub_key)} bytes): {pub_key.hex().upper()}")
    print(f"  First byte: 0x{pub_key[0]:02X}", end="")
    if pub_key[0] == 0x04:
        print(" (uncompressed EC point)")
    elif pub_key[0] in (0x02, 0x03):
        print(" (compressed EC point)")
    else:
        print(" (UNEXPECTED — not a standard EC point prefix!)")
    print()

    # Extract X coordinate
    if pub_key[0] == 0x04 and len(pub_key) == 65:
        x_coord = pub_key[1:33]
        print(f"X coordinate (bytes [1:33] of 65-byte uncompressed key):")
    elif pub_key[0] in (0x02, 0x03) and len(pub_key) == 33:
        x_coord = pub_key[1:33]
        print(f"X coordinate (bytes [1:33] of 33-byte compressed key):")
    elif len(pub_key) == 64:
        x_coord = pub_key[0:32]
        print(f"X coordinate (bytes [0:32] of 64-byte raw key — no prefix):")
    else:
        print(f"WARNING: unexpected public key length {len(pub_key)}, treating bytes [0:32] as X:")
        x_coord = pub_key[0:32]

    print(f"  {x_coord.hex().upper()}")
    print()

    # Compute CFID
    salt = struct.pack(">Q", fabric_id)   # 8-byte big-endian
    info = b"CompressedFabric"
    cfid_bytes = hkdf_sha256(ikm=x_coord, salt=salt, info=info, length=8)
    cfid = struct.unpack(">Q", cfid_bytes)[0]
    print(f"CompressedFabricID = HKDF-SHA256(IKM=X, salt=BE8(fabricID), info=\"CompressedFabric\", len=8)")
    print(f"  = {cfid:016X}")
    print()
    print("If this matches homed's expected CFID, the computation is correct.")
    print("If not, the inputs (X coordinate or fabricID) extracted from TLV are wrong.")


if __name__ == "__main__":
    main()

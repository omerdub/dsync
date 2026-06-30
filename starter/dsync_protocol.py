import struct
import zlib
from dataclasses import dataclass
from enum import IntEnum

# §1.5 — prime table for SegHash
PRIME_TABLE = [
    0x9E3779B9, 0x6B43A9B5, 0x52BCE723, 0x3F2C5E91,
    0xC2B2AE35, 0x27D4EB2F, 0x165667B9, 0x9DCC7B87,
]

MAGIC   = 0xD5CE
VERSION = 0x01
TAIL    = 0xCEFF

MAX_PAYLOAD = 65_535  # §1.1 — maximum unfragmented payload size

# §1.3 — flag bits (big-endian 2-byte field)
FLAG_COMPRESSED    = 1 << 15
FLAG_FRAGMENTED    = 1 << 14
FLAG_LAST_FRAGMENT = 1 << 13
FLAG_PRIORITY      = 1 << 12

# Header: magic(2) version(1) ftype(1) flags(2) seq(4) plen(4) seghash(4) = 18 bytes
_HEADER_FMT  = '>HBBHIII'
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)  # 18


class FrameType(IntEnum):
    HANDSHAKE     = 0x01
    SHT_ROOT      = 0x02
    SHT_PROBE     = 0x03
    SHT_RESPONSE  = 0x04
    PATCH         = 0x05
    ACK           = 0x06
    NACK          = 0x07
    SYNC_COMPLETE = 0x08


class NackCode(IntEnum):
    BAD_MAGIC     = 0x01
    BAD_CHECKSUM  = 0x02
    BAD_SEQUENCE  = 0x03
    FRAGMENT_LOST = 0x04
    UNKNOWN_TYPE  = 0x05
    OVERLOADED    = 0x06


@dataclass
class DSyncFrame:
    frame_type:   FrameType
    sequence_num: int
    flags:        int
    payload:      bytes


# ---------------------------------------------------------------------------
# §1.5 — SegHash
# ---------------------------------------------------------------------------

def seghash(data: bytes) -> int:
    """Custom 32-bit non-cryptographic checksum for frame integrity."""
    if not data:
        return 0x0000DEAD  # sentinel, not computed

    state = 0xD5CE0000  # 64-bit initial value

    chunks = [data[i:i + 8] for i in range(0, len(data), 8)]
    for i, chunk in enumerate(chunks):
        if len(chunk) < 8:
            chunk = chunk + b'\x00' * (8 - len(chunk))
        val = int.from_bytes(chunk, byteorder='big')
        state = ((state ^ val) * PRIME_TABLE[i % 8]) & 0xFFFFFFFFFFFFFFFF

    # Fold 64-bit state to 32-bit result
    result = ((state >> 32) ^ (state & 0xFFFFFFFF)) & 0xFFFFFFFF

    # Collision guard: non-empty input must never return the sentinel
    if result == 0xDEAD:
        result = 0xBEEF

    return result


# ---------------------------------------------------------------------------
# §1 — Frame encoding / decoding
# ---------------------------------------------------------------------------

def _pack_frame(frame: DSyncFrame) -> bytes:
    """Serialize a single DSyncFrame to bytes (no fragmentation)."""
    payload = frame.payload
    header = struct.pack(
        _HEADER_FMT,
        MAGIC,
        VERSION,
        int(frame.frame_type),
        frame.flags,
        frame.sequence_num,
        len(payload),
        seghash(payload),
    )
    return header + payload + struct.pack('>H', TAIL)


def encode_frame(frame: DSyncFrame, allow_fragment: bool = False):
    """
    Encode a DSyncFrame.

    Returns bytes when allow_fragment is False (raises if payload > MAX_PAYLOAD).
    Returns list[bytes] when allow_fragment is True (fragments if necessary).
    """
    if len(frame.payload) <= MAX_PAYLOAD:
        encoded = _pack_frame(frame)
        return [encoded] if allow_fragment else encoded

    if not allow_fragment:
        raise ValueError(
            f"Payload size {len(frame.payload)} exceeds {MAX_PAYLOAD} bytes; "
            "pass allow_fragment=True to enable fragmentation"
        )

    # Fragment the payload into chunks of exactly MAX_PAYLOAD bytes
    raw = frame.payload
    parts = [raw[i:i + MAX_PAYLOAD] for i in range(0, len(raw), MAX_PAYLOAD)]
    last_idx = len(parts) - 1
    result = []
    for idx, chunk in enumerate(parts):
        flags = frame.flags | FLAG_FRAGMENTED
        if idx == last_idx:
            flags |= FLAG_LAST_FRAGMENT
        frag = DSyncFrame(frame.frame_type, frame.sequence_num, flags, chunk)
        result.append(_pack_frame(frag))
    return result


def decode_frame(data: bytes) -> DSyncFrame:
    """
    Deserialize bytes into a DSyncFrame.

    Raises ValueError on bad magic, unsupported version, truncated data,
    bad tail, checksum mismatch, or unknown frame type.
    """
    if len(data) < _HEADER_SIZE + 2:
        raise ValueError(f"Frame too short ({len(data)} bytes)")

    magic, version, ftype, flags, seq_num, payload_len, stored_seg = struct.unpack_from(
        _HEADER_FMT, data, 0
    )

    if magic != MAGIC:
        raise ValueError(
            f"Invalid magic bytes: expected 0x{MAGIC:04X}, got 0x{magic:04X}"
        )

    # Bug I fix: validate protocol version
    if version != VERSION:
        raise ValueError(
            f"Unsupported protocol version: 0x{version:02X}, expected 0x{VERSION:02X}"
        )

    payload_start = _HEADER_SIZE
    payload_end   = payload_start + payload_len

    if len(data) < payload_end + 2:
        raise ValueError("Frame truncated: payload extends beyond available data")

    payload = data[payload_start:payload_end]

    tail = struct.unpack_from('>H', data, payload_end)[0]
    if tail != TAIL:
        raise ValueError(f"Invalid frame tail: 0x{tail:04X}")

    computed = seghash(payload)
    if stored_seg != computed:
        raise ValueError(
            f"checksum mismatch: stored 0x{stored_seg:08X}, computed 0x{computed:08X}"
        )

    # Bug E fix: decompress payload if FLAG_COMPRESSED is set
    if flags & FLAG_COMPRESSED:
        try:
            payload = zlib.decompress(payload)
        except zlib.error as exc:
            raise ValueError(f"Compressed payload decompression failed: {exc}") from exc

    return DSyncFrame(
        frame_type=FrameType(ftype),
        sequence_num=seq_num,
        flags=flags,
        payload=payload,
    )


def reassemble_fragments(frames: list) -> DSyncFrame:
    """Concatenate fragment payloads and return a single reassembled DSyncFrame."""
    if not frames:
        raise ValueError("No fragments provided")
    first   = frames[0]
    payload = b''.join(f.payload for f in frames)
    flags   = first.flags & ~(FLAG_FRAGMENTED | FLAG_LAST_FRAGMENT)
    return DSyncFrame(
        frame_type=first.frame_type,
        sequence_num=first.sequence_num,
        flags=flags,
        payload=payload,
    )

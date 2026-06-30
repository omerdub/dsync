import math
import struct
from typing import List

_MERSENNE = (1 << 61) - 1   # 2^61 - 1 = 2305843009213693951
_K = 3
_SEEDS = [0x1234ABCD, 0xDEADBEEF, 0xC0FFEE42]
_MAX_COUNTER = 15            # 4-bit counter maximum (saturating)


def _hash_fn(item: bytes, seed: int, m: int) -> int:
    h = seed
    for b in item:
        h = (h * 31 + b) % _MERSENNE
    return h % m


class CountingBloomFilter:
    def __init__(self, m: int = 1_000_003) -> None:
        self._m = m
        # Two 4-bit counters packed per byte → m // 2 + 1 bytes total
        self._storage = bytearray(m // 2 + 1)

    # ------------------------------------------------------------------
    # Nibble-level counter access
    # ------------------------------------------------------------------

    def _get_counter(self, pos: int) -> int:
        byte_idx = pos >> 1
        byte_val = self._storage[byte_idx]
        if pos & 1 == 0:        # even → high nibble
            return (byte_val >> 4) & 0x0F
        else:                   # odd → low nibble
            return byte_val & 0x0F

    def _set_counter(self, pos: int, value: int) -> None:
        byte_idx = pos >> 1
        byte_val = self._storage[byte_idx]
        if pos & 1 == 0:        # even → high nibble
            self._storage[byte_idx] = (byte_val & 0x0F) | ((value & 0x0F) << 4)
        else:                   # odd → low nibble
            self._storage[byte_idx] = (byte_val & 0xF0) | (value & 0x0F)

    def _positions(self, item: bytes) -> List[int]:
        return [_hash_fn(item, seed, self._m) for seed in _SEEDS]

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def add(self, item: bytes) -> None:
        """Increment all k counters for item; saturate at 15."""
        for pos in self._positions(item):
            cur = self._get_counter(pos)
            if cur < _MAX_COUNTER:
                self._set_counter(pos, cur + 1)

    def remove(self, item: bytes) -> None:
        """
        Decrement all k counters for item.
        Raise ValueError if all k counters are 0 (item was never added).
        Only decrement when all k counters are > 0 (avoid underflow).
        """
        positions = self._positions(item)
        counters = [self._get_counter(pos) for pos in positions]

        if all(c == 0 for c in counters):
            raise ValueError(f"Item not in filter (all counters are 0): {item!r}")

        if all(c > 0 for c in counters):
            for pos, cur in zip(positions, counters):
                self._set_counter(pos, cur - 1)
        # else: some counters are 0 but not all — avoid underflow, do nothing

    def __contains__(self, item: bytes) -> bool:
        """Return True iff all k counters > 0 (may produce false positives)."""
        return all(self._get_counter(pos) > 0 for pos in self._positions(item))

    def false_positive_rate(self) -> float:
        """
        Estimate FPR = (1 - e^(-k*n/m))^k
        where n = sum(all counter values) / k.
        """
        total = sum(self._get_counter(j) for j in range(self._m))
        n = total // _K
        if n == 0:
            return 0.0
        return (1.0 - math.exp(-_K * n / self._m)) ** _K

    def serialize(self) -> bytes:
        """Serialize filter state to bytes for checkpointing.

        Layout: 4-byte big-endian m  ||  m // 2 + 1 packed counter bytes.
        """
        return struct.pack('>I', self._m) + bytes(self._storage)

    @classmethod
    def deserialize(cls, data: bytes) -> "CountingBloomFilter":
        # Bug J fix: validate structure before constructing to prevent IndexError
        # on access and OOM from unbounded m values.
        if len(data) < 4:
            raise ValueError(
                f"Serialized bloom filter data too short: {len(data)} bytes"
            )
        m = struct.unpack_from('>I', data, 0)[0]
        if m == 0:
            raise ValueError("Bloom filter size m must be positive")
        expected_storage = m // 2 + 1
        if len(data) - 4 != expected_storage:
            raise ValueError(
                f"Storage size mismatch: expected {4 + expected_storage} bytes, "
                f"got {len(data)}"
            )
        bf = cls(m=m)
        bf._storage = bytearray(data[4:])
        return bf

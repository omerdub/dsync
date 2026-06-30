# DO NOT MODIFY THIS FILE
import hashlib
import os
import time


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def generate_dataset(size_bytes: int, seed: int = 42) -> bytes:
    """Deterministic pseudo-random dataset generation."""
    rng = __import__('random').Random(seed)
    return bytes(rng.randint(0, 255) for _ in range(size_bytes))


def corrupt_dataset(data: bytes, num_changes: int, seed: int = 99) -> bytes:
    """Apply num_changes random single-byte mutations."""
    rng = __import__('random').Random(seed)
    buf = bytearray(data)
    for _ in range(num_changes):
        idx = rng.randint(0, len(buf) - 1)
        buf[idx] = rng.randint(0, 255)
    return bytes(buf)


def corrupt_chunks(data: bytes, chunk_indices: list,
                   seed: int = 77, chunk_size: int = 4096) -> bytes:
    """Corrupt entire specific chunks."""
    rng = __import__('random').Random(seed)
    buf = bytearray(data)
    for ci in chunk_indices:
        start = ci * chunk_size
        end = min(start + chunk_size, len(buf))
        for i in range(start, end):
            buf[i] = rng.randint(0, 255)
    return bytes(buf)


class Timer:
    def __enter__(self):
        self._start = time.perf_counter_ns()
        return self

    def __exit__(self, *_):
        self.elapsed_us = (time.perf_counter_ns() - self._start) // 1000

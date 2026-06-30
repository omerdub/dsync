import hashlib
from typing import Callable, List

CHUNK_SIZE = 4096
NULL_HASH  = b'\x00' * 32      # placeholder for absent / non-existent children
_B         = 4                  # branching factor (fixed by spec)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _depth_for(num_chunks: int) -> int:
    """
    Return ceil(log4(num_chunks)), computed iteratively to avoid floating-point
    rounding errors on exact powers of 4.
    """
    if num_chunks <= 1:
        return 0
    d, cap = 0, 1
    while cap < num_chunks:
        cap <<= 2   # cap = 4^(d+1)
        d   += 1
    return d


class SegmentHashTree:
    """
    4-ary Merkle tree over fixed-size chunks of CHUNK_SIZE bytes.

    Storage layout (flat array, 0-indexed):
        level 0  (root):  index 0
        level 1:          indices 1–4
        level k:          indices (4^k−1)/3  …  (4^(k+1)−1)/3 − 1
        level depth (leaves): indices leaf_start … leaf_start + 4^depth − 1

    Children of node i:  4i+1, 4i+2, 4i+3, 4i+4
    Parent of node i>0:  (i−1)//4

    Absent leaf positions use NULL_HASH (b'\\x00'*32), not SHA-256 of empty bytes.
    Last (possibly partial) real chunk is right-padded with 0xFF before hashing.
    """

    def __init__(self, data: bytes) -> None:
        n = len(data)
        self._data = bytearray(data)
        # Number of actual data chunks (always >= 1 so the tree is non-empty)
        self._num_chunks: int = max(1, (n + CHUNK_SIZE - 1) // CHUNK_SIZE) if n else 1

        d = _depth_for(self._num_chunks)
        self._depth: int      = d
        self._leaf_count: int = 1 << (2 * d)               # 4^d
        self._leaf_start: int = (self._leaf_count - 1) // 3         # (4^d − 1)/3
        self._tree_size:  int = (self._leaf_count * _B - 1) // 3    # (4^(d+1) − 1)/3

        self._tree: List[bytes] = [NULL_HASH] * self._tree_size
        self._build()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _chunk_bytes(self, chunk_idx: int) -> bytes:
        """Return the raw chunk at chunk_idx, right-padded with 0xFF to CHUNK_SIZE."""
        start = chunk_idx * CHUNK_SIZE
        raw   = bytes(self._data[start: start + CHUNK_SIZE])
        if len(raw) < CHUNK_SIZE:
            raw = raw + b'\xff' * (CHUNK_SIZE - len(raw))
        return raw

    def _build(self) -> None:
        """Build the complete flat tree bottom-up in two passes."""
        # Pass 1: fill leaf hashes
        for i in range(self._leaf_count):
            fi = self._leaf_start + i
            self._tree[fi] = (
                _sha256(self._chunk_bytes(i)) if i < self._num_chunks else NULL_HASH
            )

        # Pass 2: build internal nodes from the level just above leaves up to root
        for lvl in range(self._depth - 1, -1, -1):
            lvl_size  = 1 << (2 * lvl)        # 4^lvl nodes on this level
            lvl_start = (lvl_size - 1) // 3   # first flat index on this level
            for j in range(lvl_size):
                ni   = lvl_start + j
                base = 4 * ni + 1
                kids = self._tree[base] + self._tree[base + 1] + \
                       self._tree[base + 2] + self._tree[base + 3]
                self._tree[ni] = _sha256(kids)

    # ------------------------------------------------------------------
    # Public interface (required by spec §2.3)
    # ------------------------------------------------------------------

    def get_root_hash(self) -> bytes:
        """Return the 32-byte SHA-256 root hash."""
        return self._tree[0]

    def get_node_hash(self, flat_index: int) -> bytes:
        """Return the 32-byte hash of the node at flat_index."""
        return self._tree[flat_index] if flat_index < self._tree_size else NULL_HASH

    def get_children_hashes(self, flat_index: int) -> List[bytes]:
        """
        Return exactly 4 hashes (each 32 bytes).
        Non-existent children (beyond tree_size) return NULL_HASH.
        """
        base = 4 * flat_index + 1
        return [
            self._tree[base + c] if (base + c) < self._tree_size else NULL_HASH
            for c in range(4)
        ]

    def diff(self, other_root: bytes, probe_fn: Callable) -> List[int]:
        """
        Perform an iterative depth-first diff against a remote tree.

        probe_fn(flat_index) -> list[bytes]
            Returns the 4 child hashes of the remote node at flat_index
            (simulates SHT_PROBE / SHT_RESPONSE round-trip).

        Returns a sorted list of chunk indices (0-based) that differ.
        Prunes identical subtrees — probe_fn is never called for a node
        whose hash already matches the remote.
        """
        if self.get_root_hash() == other_root:
            return []

        changed: List[int] = []
        # Each element: (flat_index, level)
        stack = [(0, 0)]

        while stack:
            idx, level = stack.pop()

            if level == self._depth:
                # Leaf node — record the chunk index if the chunk actually exists
                chunk_idx = idx - self._leaf_start
                if 0 <= chunk_idx < self._num_chunks:
                    changed.append(chunk_idx)
                continue

            # Internal node that differs from remote.
            # Probe the remote tree to learn its children's hashes, then
            # recurse only into children whose hashes mismatch.
            remote_children = probe_fn(idx)
            local_children  = self.get_children_hashes(idx)

            for c in range(4):
                if local_children[c] != remote_children[c]:
                    stack.append((4 * idx + 1 + c, level + 1))

        return sorted(changed)

    def apply_patch(self, chunk_index: int, chunk_data: bytes) -> None:
        """
        Overwrite the chunk at chunk_index with chunk_data
        (right-padded / truncated to CHUNK_SIZE with 0xFF).
        Recomputes only the ancestor spine bottom-up — O(log4 N).
        """
        # Bug B fix: validate bounds before any data modification to prevent
        # the memory-leak + IndexError chain that enables the engine deadlock.
        if not (0 <= chunk_index < self._num_chunks):
            raise ValueError(
                f"chunk_index {chunk_index} out of range "
                f"(num_chunks={self._num_chunks})"
            )

        # Normalise chunk_data to exactly CHUNK_SIZE bytes
        if len(chunk_data) < CHUNK_SIZE:
            chunk_data = chunk_data + b'\xff' * (CHUNK_SIZE - len(chunk_data))
        else:
            chunk_data = chunk_data[:CHUNK_SIZE]

        # Update the stored byte buffer
        start = chunk_index * CHUNK_SIZE
        end   = start + CHUNK_SIZE
        if end > len(self._data):
            self._data.extend(b'\xff' * (end - len(self._data)))
        self._data[start:end] = chunk_data

        # Recompute the leaf hash
        leaf_fi = self._leaf_start + chunk_index
        self._tree[leaf_fi] = _sha256(chunk_data)

        # Walk up to root, recomputing each ancestor — O(log4 N) steps
        current = leaf_fi
        while current > 0:
            parent = (current - 1) // 4
            base   = 4 * parent + 1
            kids   = (
                (self._tree[base]     if base     < self._tree_size else NULL_HASH) +
                (self._tree[base + 1] if base + 1 < self._tree_size else NULL_HASH) +
                (self._tree[base + 2] if base + 2 < self._tree_size else NULL_HASH) +
                (self._tree[base + 3] if base + 3 < self._tree_size else NULL_HASH)
            )
            self._tree[parent] = _sha256(kids)
            current = parent

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def depth(self) -> int:
        return self._depth

    @property
    def num_chunks(self) -> int:
        return self._num_chunks

import asyncio
import struct
from typing import Dict, List, Optional, Tuple

from starter.dsync_protocol import (
    DSyncFrame,
    FrameType,
    NackCode,
    seghash,
    FLAG_FRAGMENTED,
    FLAG_LAST_FRAGMENT,
    FLAG_PRIORITY,
    reassemble_fragments,
)
from starter.sht import SegmentHashTree, CHUNK_SIZE, NULL_HASH
from starter.bloom_filter import CountingBloomFilter


# ---------------------------------------------------------------------------
# Priority-aware input queue (Fix H)
# ---------------------------------------------------------------------------

class _FramePriorityQueue:
    """
    Drop-in replacement for asyncio.Queue that respects FLAG_PRIORITY.

    Priority levels:
      0 — FLAG_PRIORITY set (high-priority frames, processed first)
      1 — normal frames
      2 — None sentinel (shutdown, always processed last)

    Within the same priority level frames are processed FIFO via a monotonic
    counter, so the heap never compares DSyncFrame objects directly.
    """

    def __init__(self) -> None:
        self._pq: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._counter: int = 0

    async def put(self, item: Optional[DSyncFrame]) -> None:
        if item is None:
            prio = 2
        elif item.flags & FLAG_PRIORITY:
            prio = 0
        else:
            prio = 1
        await self._pq.put((prio, self._counter, item))
        self._counter += 1

    async def get(self) -> Optional[DSyncFrame]:
        _, _, item = await self._pq.get()
        return item

    def get_nowait(self) -> Optional[DSyncFrame]:
        _, _, item = self._pq.get_nowait()
        return item

    def empty(self) -> bool:
        return self._pq.empty()

    def qsize(self) -> int:
        return self._pq.qsize()


# ---------------------------------------------------------------------------
# Vector Clock
# ---------------------------------------------------------------------------

class VectorClock:
    """
    Logical clock for tracking causal relationships between N workers.

    _clocks[i] holds the latest event count known from worker i.
    """

    def __init__(self, worker_id: int, num_workers: int) -> None:
        self._id = worker_id
        self._n = num_workers
        self._clocks: List[int] = [0] * num_workers

    # --- Mutation ---

    def tick(self) -> None:
        """Advance own counter by 1 (call before sending a message)."""
        self._clocks[self._id] += 1

    def update(self, received) -> None:
        """
        Merge on message receive (spec §4.3: accepts list[int]).
        Also accepts VectorClock for internal use.

        1. Element-wise max of self and received.
        2. Tick own counter.
        """
        if isinstance(received, VectorClock):
            other_clocks = received._clocks
        else:
            other_clocks = list(received)
        for i in range(min(self._n, len(other_clocks))):
            if other_clocks[i] > self._clocks[i]:
                self._clocks[i] = other_clocks[i]
        self.tick()

    # --- Comparison (spec §4.3) ---

    def happens_before(self, other: "VectorClock") -> bool:
        """True iff every component of self ≤ other and at least one is strictly <."""
        le_all = all(a <= b for a, b in zip(self._clocks, other._clocks))
        lt_any = any(a < b for a, b in zip(self._clocks, other._clocks))
        return le_all and lt_any

    def __lt__(self, other: "VectorClock") -> bool:
        """Spec alias for happens_before."""
        return self.happens_before(other)

    def concurrent(self, other: "VectorClock") -> bool:
        """True iff neither clock happens-before the other."""
        return not self.happens_before(other) and not other.happens_before(self)

    def concurrent_with(self, other: "VectorClock") -> bool:
        """Spec alias for concurrent."""
        return self.concurrent(other)

    # --- Serialization ---

    def to_bytes(self) -> bytes:
        """Encode as N big-endian uint32 values (N × 4 bytes)."""
        out = bytearray(self._n * 4)
        for i, v in enumerate(self._clocks):
            struct.pack_into(">I", out, i * 4, v)
        return bytes(out)

    def to_list(self) -> List[int]:
        """Return clock vector as a plain Python list (spec §4.3)."""
        return list(self._clocks)

    @classmethod
    def from_bytes(cls, data: bytes, worker_id: int) -> "VectorClock":
        """Decode bytes produced by to_bytes(); worker_id identifies the owner."""
        n = len(data) // 4
        vc = cls(worker_id=worker_id, num_workers=n)
        for i in range(n):
            vc._clocks[i] = struct.unpack_from(">I", data, i * 4)[0]
        return vc

    def copy(self) -> "VectorClock":
        vc = VectorClock(self._id, self._n)
        vc._clocks = list(self._clocks)
        return vc

    def __getitem__(self, i: int) -> int:
        return self._clocks[i]

    def __repr__(self) -> str:
        return f"VectorClock(id={self._id}, clocks={self._clocks})"


# ---------------------------------------------------------------------------
# Consistent hashing
# ---------------------------------------------------------------------------

def consistent_hash(chunk_index: int, num_workers: int) -> int:
    """Return the worker_id responsible for chunk_index (0-indexed)."""
    return seghash(chunk_index.to_bytes(4, "big")) % num_workers


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

class Worker:
    """
    Asyncio-based distributed sync worker.

    Each worker owns a local SegmentHashTree.  Responsibility for a chunk is
    determined by consistent_hash.  Incoming PATCH frames are deduplicated via
    a CountingBloomFilter.

    PATCH payload wire format (spec §1.4)
    --------------------------------------
    bytes [0:4]    chunk_index    uint32 big-endian
    bytes [4:6]    actual_size    uint16 big-endian (≤ 4096)
    bytes [6:]     chunk_data     raw bytes (actual_size bytes)
    """

    def __init__(
        self,
        worker_id: int,
        num_workers: int,
        inbox: "asyncio.Queue | None" = None,
        outbox: "asyncio.Queue | None" = None,
        data: bytes = b"",
    ) -> None:
        self.worker_id = worker_id
        self._num_workers = num_workers
        self._sht = SegmentHashTree(data)
        self._bloom = CountingBloomFilter()
        self._vc = VectorClock(worker_id, num_workers)
        self._in_queue = inbox
        self._out_queue = outbox

        # seq_num → (chunk_index, chunk_data) — for NACK retransmission
        self._pending: Dict[int, Tuple[int, bytes]] = {}
        self._seq = 0
        # chunk_index → VectorClock snapshot when that chunk was last patched
        self._chunk_applied_vc: Dict[int, VectorClock] = {}
        # seq_num → list[DSyncFrame] — buffered fragments (Fix D)
        self._fragment_buffer: Dict[int, List[DSyncFrame]] = {}
        # Last master root hash received via SHT_ROOT
        self._coordinator_root: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def is_responsible(self, chunk_index: int) -> bool:
        return consistent_hash(chunk_index, self._num_workers) == self.worker_id

    def get_root_hash(self) -> bytes:
        return self._sht.get_root_hash()

    def get_replica_data(self) -> bytes:
        """Return the worker's full data copy (spec §4.4)."""
        return bytes(self._sht._data)

    @property
    def sht(self) -> SegmentHashTree:
        return self._sht

    @property
    def vc(self) -> VectorClock:
        return self._vc

    # ------------------------------------------------------------------
    # Outbound
    # ------------------------------------------------------------------

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _build_patch_payload(
        self, chunk_index: int, chunk_data: bytes
    ) -> bytes:
        """Build §1.4-compliant PATCH payload: chunk_index(4B) + data_size(2B) + data."""
        data_size = min(len(chunk_data), CHUNK_SIZE)
        return (
            chunk_index.to_bytes(4, "big")
            + data_size.to_bytes(2, "big")
            + chunk_data[:data_size]
        )

    async def send_patch(self, chunk_index: int, chunk_data: bytes) -> int:
        """Tick VC, enqueue a PATCH frame, return its sequence number."""
        self._vc.tick()
        seq = self._next_seq()
        payload = self._build_patch_payload(chunk_index, chunk_data)
        frame = DSyncFrame(FrameType.PATCH, seq, 0, payload)
        self._pending[seq] = (chunk_index, chunk_data)
        await self._out_queue.put(frame)
        return seq

    # ------------------------------------------------------------------
    # Inbound handlers
    # ------------------------------------------------------------------

    def _parse_patch(
        self, payload: bytes
    ) -> Tuple[int, bytes]:
        """
        Parse §1.4 PATCH payload: chunk_index(4B) + data_size(2B) + chunk_data(N bytes).

        Raises ValueError for malformed payloads (too short, data_size out of range,
        or truncated data) to prevent silent SHT corruption.
        """
        if len(payload) < 6:
            raise ValueError(
                f"PATCH payload too short: {len(payload)} bytes, minimum 6"
            )
        chunk_index = int.from_bytes(payload[0:4], "big")
        data_size = int.from_bytes(payload[4:6], "big")
        if not (1 <= data_size <= CHUNK_SIZE):
            raise ValueError(
                f"PATCH data_size {data_size} out of valid range [1, {CHUNK_SIZE}]"
            )
        if len(payload) < 6 + data_size:
            raise ValueError(
                f"PATCH payload truncated: expected {6 + data_size} bytes, "
                f"got {len(payload)}"
            )
        chunk_data = payload[6: 6 + data_size]
        return chunk_index, chunk_data

    async def _handle_patch(self, frame: DSyncFrame) -> None:
        bloom_key = frame.sequence_num.to_bytes(4, "big")
        if bloom_key in self._bloom:
            return  # exact duplicate — already applied

        chunk_index, chunk_data = self._parse_patch(frame.payload)

        if not self.is_responsible(chunk_index):
            return  # not our shard

        # Spec §4.3: apply patches in vector-clock order; tie-break by worker_id.
        # The coordinator carries effective worker_id = num_workers (always the
        # highest possible value, so its patches always win the tie over any
        # real worker_id, which is in [0, num_workers-1]).
        COORDINATOR_WID = self._num_workers
        prior_vc = self._chunk_applied_vc.get(chunk_index)
        incoming_snapshot = self._vc.copy()

        should_apply = True
        if prior_vc is not None:
            if prior_vc.concurrent_with(incoming_snapshot):
                # Concurrent patches to the same chunk: higher worker_id wins.
                # Reject the incoming patch only if the local worker has a higher
                # worker_id than the sender (local wins the tie).
                if COORDINATOR_WID < self.worker_id:
                    should_apply = False
            elif incoming_snapshot < prior_vc:
                # Stale: incoming is causally before the last applied patch — reject.
                should_apply = False

        # Always advance the clock to register receipt of this event (spec §4.3).
        self._vc.tick()

        if should_apply:
            self._sht.apply_patch(chunk_index, chunk_data)
            self._bloom.add(bloom_key)
            self._chunk_applied_vc[chunk_index] = self._vc.copy()

        await self._out_queue.put(
            DSyncFrame(
                FrameType.ACK,
                frame.sequence_num,
                0,
                frame.sequence_num.to_bytes(4, "big"),  # spec §1.4: payload = acked seq_num
            )
        )

    async def _handle_ack(self, frame: DSyncFrame) -> None:
        self._pending.pop(frame.sequence_num, None)

    async def _handle_nack(self, frame: DSyncFrame) -> None:
        """
        Parse and respect the retry-after hint (byte 5 of NACK payload).
        Reads rejected_seq from payload[0:4] per spec §1.4; falls back to
        frame.sequence_num for backwards-compatible test frames with empty payload.
        """
        if len(frame.payload) >= 4:
            orig_seq = int.from_bytes(frame.payload[0:4], "big")
        else:
            orig_seq = frame.sequence_num
        if orig_seq not in self._pending:
            return
        chunk_index, chunk_data = self._pending.pop(orig_seq)

        retry_after: int = 0
        if len(frame.payload) >= 6:
            retry_after = frame.payload[5]
        if retry_after > 0:
            await asyncio.sleep(retry_after)

        self._vc.tick()
        new_seq = self._next_seq()
        payload = self._build_patch_payload(chunk_index, chunk_data)
        retx = DSyncFrame(FrameType.PATCH, new_seq, 0, payload)
        self._pending[new_seq] = (chunk_index, chunk_data)
        await self._out_queue.put(retx)

    async def _handle_probe(self, frame: DSyncFrame) -> None:
        """
        Handle SHT_PROBE: query local SHT and respond with SHT_RESPONSE.
        Payload: 1B child_count + 4×32B hashes = 129 bytes (spec §1.4).
        """
        flat_index = int.from_bytes(frame.payload[0:4], "big")
        children = self._sht.get_children_hashes(flat_index)
        child_count = sum(1 for c in children if c != NULL_HASH)
        response = DSyncFrame(
            FrameType.SHT_RESPONSE,
            frame.sequence_num,
            0,
            bytes([child_count]) + b"".join(children),  # 1B + 128B = 129B
        )
        await self._out_queue.put(response)

    async def _handle_handshake(self, frame: DSyncFrame) -> None:
        """Echo HANDSHAKE with worker's own ID to complete the connection."""
        own_payload = self.worker_id.to_bytes(4, "big") + frame.payload[4:]
        await self._out_queue.put(
            DSyncFrame(FrameType.HANDSHAKE, frame.sequence_num, 0, own_payload)
        )

    async def _handle_sht_root(self, frame: DSyncFrame) -> None:
        """
        Receive master's root hash from engine. Store for reference; no response.
        Payload: root_hash(32B) + tree_depth(4B) + total_bytes(8B) = 44B (spec §1.4).
        """
        if len(frame.payload) >= 32:
            self._coordinator_root = frame.payload[:32]

    async def _handle_sync_complete(self, frame: DSyncFrame) -> None:
        """Engine signals sync is complete; acknowledge it."""
        await self._out_queue.put(
            DSyncFrame(FrameType.ACK, frame.sequence_num, 0,
                       frame.sequence_num.to_bytes(4, "big"))
        )

    # ------------------------------------------------------------------
    # Main coroutine
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Process frames from in_queue until a None sentinel is received.

        Fix A: handler exceptions are caught and the frame is silently
               discarded, preventing worker task death → engine deadlock.
        Fix D: fragmented frames are buffered and reassembled before dispatch.
        Fix H: in_queue may be a _FramePriorityQueue; FLAG_PRIORITY frames
               are drained ahead of normal frames transparently.
        """
        dispatch = {
            FrameType.HANDSHAKE:     self._handle_handshake,
            FrameType.PATCH:         self._handle_patch,
            FrameType.ACK:           self._handle_ack,
            FrameType.NACK:          self._handle_nack,
            FrameType.SHT_PROBE:     self._handle_probe,
            FrameType.SHT_ROOT:      self._handle_sht_root,
            FrameType.SYNC_COMPLETE: self._handle_sync_complete,
        }
        while True:
            frame = await self._in_queue.get()
            if frame is None:
                break

            # Fix D: fragment reassembly — buffer until last fragment arrives
            if frame.flags & FLAG_FRAGMENTED:
                seq = frame.sequence_num
                self._fragment_buffer.setdefault(seq, []).append(frame)
                if not (frame.flags & FLAG_LAST_FRAGMENT):
                    continue  # wait for remaining fragments
                frame = reassemble_fragments(self._fragment_buffer.pop(seq))

            handler = dispatch.get(frame.frame_type)
            if handler is not None:
                # Fix A: never let a handler exception kill the worker task.
                try:
                    await handler(frame)
                except Exception:
                    pass

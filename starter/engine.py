import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from starter.dsync_protocol import DSyncFrame, FrameType
from starter.sht import SegmentHashTree, CHUNK_SIZE, NULL_HASH
from starter.bloom_filter import CountingBloomFilter
from starter.worker import Worker, consistent_hash, _FramePriorityQueue


class _AwaitableNone:
    """
    Returned by _set_worker_data so benchmark.py can call it as
    ``await engine._set_worker_data(...)``, while test_integration.py
    calls it synchronously (the return value is simply ignored).

    __await__ returns an immediately-exhausted iterator, so
    ``yield from iter(())`` (what ``await`` desugars to) completes at once.
    """
    __slots__ = ()

    def __await__(self):
        return iter(())


@dataclass
class SyncReport:
    synced_workers: int
    probe_calls_total: int
    patches_sent: int
    retransmissions: int
    patches_per_worker: Dict[int, int] = field(default_factory=dict)
    total_bytes_transferred: int = 0
    total_frames_sent: int = 0
    duration_us: int = 0


# Maximum consecutive drops per PATCH before forcing a send regardless of
# drop_rate.  Prevents the retry loop from running forever at high drop_rates.
_MAX_CONSEC_DROPS = 20


class DSyncEngine:
    """
    Coordinator for the distributed sync protocol.

    Holds the authoritative master dataset and N Workers.  sync_all() runs
    each worker's protocol session concurrently (asyncio.gather) and returns
    a SyncReport with aggregate statistics.

    Supports two construction modes:
      (a) DSyncEngine(master_data, num_workers) — immediate init (used by tests)
      (b) DSyncEngine(num_workers=N) + await load_master(data) — used by benchmark

    Protocol per worker (spec §1.4)
    ---------------------------------
    HANDSHAKE → SHT_ROOT → (SHT_PROBE / SHT_RESPONSE)* → (PATCH / ACK)* →
    SYNC_COMPLETE → shutdown
    """

    _worker_response_timeout: float = 30.0

    def __init__(
        self,
        master_data: bytes = None,
        num_workers: int = 4,
        drop_rate: float = 0.0,
        seed: int = 0,
    ) -> None:
        self._num_workers = num_workers
        self._drop_rate = drop_rate
        self._seed = seed
        self._seq = 0
        if master_data is not None:
            self._master_data: bytearray = bytearray(master_data)
            self._master_sht: Optional[SegmentHashTree] = SegmentHashTree(master_data)
            self._workers: List[Worker] = [
                Worker(worker_id=i, num_workers=num_workers, data=master_data)
                for i in range(num_workers)
            ]
        else:
            self._master_data = bytearray()
            self._master_sht = None
            self._workers = []
        self._in_queues: List = []
        self._out_queues: List[asyncio.Queue] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def load_master(self, master: bytes) -> None:
        """Async initialiser used by benchmark.py after DSyncEngine(num_workers=N)."""
        self._master_data = bytearray(master)
        self._master_sht = SegmentHashTree(master)
        self._workers = [
            Worker(worker_id=i, num_workers=self._num_workers, data=master)
            for i in range(self._num_workers)
        ]

    def _set_worker_data(self, data: bytes) -> _AwaitableNone:
        """
        Replace every worker's SHT with a fresh tree built from ``data``,
        clearing accumulated patch history and the Bloom filter.

        Returns _AwaitableNone so benchmark.py can call this as
        ``await engine._set_worker_data(...)`` without TypeError.
        """
        for w in self._workers:
            w._sht = SegmentHashTree(data)
            w._bloom = CountingBloomFilter()
        return _AwaitableNone()

    async def verify(self) -> bool:
        """
        Return True iff every chunk's responsible worker holds the correct leaf hash.
        """
        leaf_start = self._master_sht._leaf_start
        for chunk_idx in range(self._master_sht.num_chunks):
            master_leaf = self._master_sht.get_node_hash(leaf_start + chunk_idx)
            owner = consistent_hash(chunk_idx, self._num_workers)
            worker_leaf = self._workers[owner]._sht.get_node_hash(
                self._workers[owner]._sht._leaf_start + chunk_idx
            )
            if master_leaf != worker_leaf:
                return False
        return True

    def get_master_root(self) -> bytes:
        return self._master_sht.get_root_hash()

    async def update_master(self, offset: int, new_data: bytes) -> None:
        """
        Update master bytes starting at offset and patch the SHT incrementally.
        Touches only the affected chunks → O(log₄ N) per chunk, not a full rebuild.
        """
        end = offset + len(new_data)
        if end > len(self._master_data):
            self._master_data.extend(b"\x00" * (end - len(self._master_data)))
        self._master_data[offset:end] = new_data

        first_chunk = offset // CHUNK_SIZE
        last_chunk = (end - 1) // CHUNK_SIZE
        data_len = len(self._master_data)  # total logical bytes after the write
        for chunk_idx in range(first_chunk, last_chunk + 1):
            s = chunk_idx * CHUNK_SIZE
            # Bound by the actual buffer length, not `end`, so that:
            # - Full chunks (s + CHUNK_SIZE <= data_len) pass all 4096 bytes; and
            # - A genuine partial last chunk (s + CHUNK_SIZE > data_len) passes
            #   only the real bytes, triggering apply_patch()'s 0xFF padding.
            self._master_sht.apply_patch(
                chunk_idx,
                bytes(self._master_data[s: min(s + CHUNK_SIZE, data_len)]),
            )

    # ------------------------------------------------------------------
    # sync_all
    # ------------------------------------------------------------------

    async def sync_all(self) -> SyncReport:
        """
        Sync all workers with the master dataset concurrently.
        Returns a SyncReport with aggregate statistics.
        """
        self._seq = 0
        start_ns = time.perf_counter_ns()

        self._in_queues = [_FramePriorityQueue() for _ in range(self._num_workers)]
        self._out_queues = [asyncio.Queue() for _ in range(self._num_workers)]
        for i, w in enumerate(self._workers):
            w._in_queue = self._in_queues[i]
            w._out_queue = self._out_queues[i]

        rng = random.Random(self._seed)

        worker_tasks = [
            asyncio.create_task(self._workers[i].run())
            for i in range(self._num_workers)
        ]

        # Cache: worker_root_hash → (changed_chunks, probe_count).
        diff_cache: Dict[bytes, Tuple[List[int], int]] = {}

        try:
            results: List[Tuple] = await asyncio.gather(
                *[self._sync_one_worker(i, self._drop_rate, rng, diff_cache)
                  for i in range(self._num_workers)]
            )
        except BaseException:
            for t in worker_tasks:
                t.cancel()
            await asyncio.gather(*worker_tasks, return_exceptions=True)
            raise

        for i in range(self._num_workers):
            await self._in_queues[i].put(None)

        done, pending = await asyncio.wait(
            worker_tasks,
            timeout=self._worker_response_timeout,
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*worker_tasks, return_exceptions=True)

        duration_us = (time.perf_counter_ns() - start_ns) // 1000
        total_probes  = sum(r[0] for r in results)
        total_patches = sum(r[1] for r in results)
        total_retx    = sum(r[2] for r in results)
        total_bytes   = sum(r[3] for r in results)
        total_frames  = sum(r[5] for r in results)
        synced = sum(1 for r in results if r[4])
        patches_per_worker = {i: results[i][1] for i in range(self._num_workers)}

        return SyncReport(
            synced_workers=synced,
            probe_calls_total=total_probes,
            patches_sent=total_patches,
            retransmissions=total_retx,
            patches_per_worker=patches_per_worker,
            total_bytes_transferred=total_bytes,
            total_frames_sent=total_frames,
            duration_us=duration_us,
        )

    # ------------------------------------------------------------------
    # Per-worker protocol session
    # ------------------------------------------------------------------

    async def _sync_one_worker(
        self,
        worker_id: int,
        drop_rate: float,
        rng: random.Random,
        diff_cache: Dict[bytes, Tuple[List[int], int]],
    ) -> Tuple:
        """
        Run the full protocol for one worker.
        Returns (probe_calls, patches_sent, retransmissions, bytes_transferred,
                 success, frames_sent).
        """
        try:
            start_ns = time.perf_counter_ns()
            frames_sent = 0

            # 1. HANDSHAKE (8-byte payload per spec §1.4)
            await self._handshake(worker_id)
            frames_sent += 1

            # 2. Fetch worker root hash via direct SHT access.
            worker_root = self._workers[worker_id].get_root_hash()

            # 3. Send SHT_ROOT to worker (no response expected).
            await self._send_sht_root(worker_id)
            frames_sent += 1

            # 4. Compute diff via async SHT_PROBE/SHT_RESPONSE exchange.
            if worker_root in diff_cache:
                changed_chunks, probe_calls = diff_cache[worker_root]
            else:
                changed_chunks, probe_calls = await self._diff_via_probes(
                    worker_id, worker_root
                )
                diff_cache[worker_root] = (changed_chunks, probe_calls)
            frames_sent += probe_calls  # one SHT_PROBE frame per probe call

            # 5. Send PATCH for each chunk this worker is responsible for.
            total_patches = 0
            total_retx = 0
            total_bytes = 0
            for chunk_idx in changed_chunks:
                if consistent_hash(chunk_idx, self._num_workers) != worker_id:
                    continue
                s = chunk_idx * CHUNK_SIZE
                chunk_data = bytes(self._master_data[s: s + CHUNK_SIZE])
                p, r = await self._send_patch_with_retry(
                    worker_id, chunk_idx, chunk_data, drop_rate, rng
                )
                total_patches += p
                total_retx += r
                total_bytes += len(chunk_data)
                frames_sent += p

            # 6. SYNC_COMPLETE with 16-byte payload (spec §1.4).
            duration_us = (time.perf_counter_ns() - start_ns) // 1000
            await self._sync_complete(worker_id, total_patches, total_bytes, duration_us)
            frames_sent += 1

            return probe_calls, total_patches, total_retx, total_bytes, True, frames_sent

        except Exception:
            return 0, 0, 0, 0, False, 0

    # ------------------------------------------------------------------
    # Diff via async SHT_PROBE / SHT_RESPONSE exchange
    # ------------------------------------------------------------------

    async def _diff_via_probes(
        self, worker_id: int, worker_root: bytes
    ) -> Tuple[List[int], int]:
        """
        Iterative DFS diff using async SHT_PROBE/SHT_RESPONSE frame exchange.
        Engine sends SHT_PROBE frames to the worker's in_queue; worker responds
        with SHT_RESPONSE frames in its out_queue.

        Returns (sorted changed chunk indices, probe call count).
        """
        if self._master_sht.get_root_hash() == worker_root:
            return [], 0

        depth = self._master_sht.depth
        leaf_start = self._master_sht._leaf_start
        num_chunks = self._master_sht.num_chunks

        changed: List[int] = []
        probe_calls = 0
        stack = [(0, 0)]  # (flat_index, level)

        while stack:
            idx, level = stack.pop()

            if level == depth:
                chunk_idx = idx - leaf_start
                if 0 <= chunk_idx < num_chunks:
                    changed.append(chunk_idx)
                continue

            # Send SHT_PROBE to worker
            seq = self._next_seq()
            await self._in_queues[worker_id].put(
                DSyncFrame(FrameType.SHT_PROBE, seq, 0, idx.to_bytes(4, "big"))
            )
            probe_calls += 1

            # Read SHT_RESPONSE: 1B child_count + 4×32B = 129B
            resp = await self._await_response(worker_id)
            if len(resp.payload) >= 129:
                worker_children = [
                    resp.payload[1 + c * 32: 1 + (c + 1) * 32]
                    for c in range(4)
                ]
            else:
                worker_children = [NULL_HASH] * 4

            local_children = self._master_sht.get_children_hashes(idx)

            for c in range(4):
                if local_children[c] != worker_children[c]:
                    stack.append((4 * idx + 1 + c, level + 1))

        return sorted(changed), probe_calls

    # ------------------------------------------------------------------
    # Protocol helpers
    # ------------------------------------------------------------------

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    async def _await_response(self, worker_id: int) -> DSyncFrame:
        """
        Await a response from worker_id's out_queue with a deadline.
        Raises RuntimeError when the worker does not respond in time.
        """
        try:
            return await asyncio.wait_for(
                self._out_queues[worker_id].get(),
                timeout=self._worker_response_timeout,
            )
        except asyncio.TimeoutError:
            raise RuntimeError(
                f"Worker {worker_id} did not respond within "
                f"{self._worker_response_timeout}s — marking session as failed"
            )

    async def _handshake(self, worker_id: int) -> None:
        """Send HANDSHAKE with 8-byte payload per spec §1.4: worker_id(4B) + 0x04(1B) + 0x1000(2B) + 0x03(1B)."""
        seq = self._next_seq()
        payload = (
            worker_id.to_bytes(4, "big")
            + b'\x04'
            + (4096).to_bytes(2, "big")
            + b'\x03'
        )
        await self._in_queues[worker_id].put(
            DSyncFrame(FrameType.HANDSHAKE, seq, 0, payload)
        )
        await self._await_response(worker_id)

    async def _send_sht_root(self, worker_id: int) -> None:
        """
        Send SHT_ROOT with 44-byte payload per spec §1.4:
        root_hash(32B) + tree_depth(4B) + total_bytes(8B).
        No response is expected from the worker.
        """
        seq = self._next_seq()
        payload = (
            self._master_sht.get_root_hash()
            + self._master_sht.depth.to_bytes(4, "big")
            + len(self._master_data).to_bytes(8, "big")
        )
        await self._in_queues[worker_id].put(
            DSyncFrame(FrameType.SHT_ROOT, seq, 0, payload)
        )

    async def _sync_complete(
        self,
        worker_id: int,
        patches_sent: int = 0,
        bytes_sent: int = 0,
        duration_us: int = 0,
    ) -> None:
        """
        Send SYNC_COMPLETE with 16-byte §1.4 payload:
        total_patches(4B) + total_bytes(4B) + duration_µs(8B).
        """
        seq = self._next_seq()
        payload = (
            min(patches_sent, 0xFFFFFFFF).to_bytes(4, "big")
            + min(bytes_sent, 0xFFFFFFFF).to_bytes(4, "big")
            + min(duration_us, 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
        )
        await self._in_queues[worker_id].put(
            DSyncFrame(FrameType.SYNC_COMPLETE, seq, 0, payload)
        )
        await self._await_response(worker_id)

    def _build_patch_payload(self, chunk_idx: int, chunk_data: bytes) -> bytes:
        """Build §1.4-compliant PATCH payload: chunk_index(4B) + data_size(2B) + data."""
        data_size = min(len(chunk_data), CHUNK_SIZE)
        return (
            chunk_idx.to_bytes(4, "big")
            + data_size.to_bytes(2, "big")
            + chunk_data[:data_size]
        )

    async def _send_patch_with_retry(
        self,
        worker_id: int,
        chunk_idx: int,
        chunk_data: bytes,
        drop_rate: float,
        rng: random.Random,
    ) -> Tuple[int, int]:
        """
        Send PATCH to worker with simulated packet drops.
        Returns (patches_sent, retransmissions).
        """
        in_q = self._in_queues[worker_id]
        patches_sent = 0
        retransmissions = 0
        consec_drops = 0

        while True:
            if consec_drops < _MAX_CONSEC_DROPS and rng.random() < drop_rate:
                retransmissions += 1
                consec_drops += 1
                await asyncio.sleep(0)
                continue
            consec_drops = 0

            seq = self._next_seq()
            payload = self._build_patch_payload(chunk_idx, chunk_data)
            await in_q.put(DSyncFrame(FrameType.PATCH, seq, 0, payload))
            patches_sent += 1

            resp = await self._await_response(worker_id)
            if resp.frame_type == FrameType.ACK:
                break
            retransmissions += 1

        return patches_sent, retransmissions

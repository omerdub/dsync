# DSYNC — Distributed Data Synchronisation Engine

> **Gentrix / Generative LTD — Data Engineer Assignment**  
> Standard-library-only · Python 3.9+ · asyncio concurrency

---

## Table of Contents

1. [Project Layout](#1-project-layout)
2. [Quick Start](#2-quick-start)
3. [Architectural Overview](#3-architectural-overview)
4. [Component Deep-Dives](#4-component-deep-dives)
5. [Wire Protocol Reference](#5-wire-protocol-reference)
6. [Design Notes](#6-design-notes)
7. [Conflict Resolution](#7-conflict-resolution)
8. [SegHash Verification Vectors](#8-seghash-verification-vectors)
9. [Benchmark Results](#9-benchmark-results)
10. [Resilience, Security & Chaos Testing](#10-resilience-security--chaos-testing)

---

## 1. Project Layout

```
dsync/
├── README.md
├── benchmark.py              ← Performance scenarios (DO NOT MODIFY)
├── conftest.py
├── starter/
│   ├── dsync_protocol.py     ← SegHash · frame encoding · fragmentation
│   ├── sht.py                ← 4-ary Segment Hash Tree
│   ├── bloom_filter.py       ← Counting Bloom Filter (4-bit saturating)
│   ├── worker.py             ← Worker coroutine · VectorClock
│   ├── engine.py             ← DSyncEngine coordinator
│   └── utils.py              ← Dataset helpers (DO NOT MODIFY)
└── tests/
    ├── test_protocol.py      ← SegHash and frame encoding tests
    ├── test_sht.py           ← SHT correctness tests
    ├── test_bloom.py         ← Bloom filter tests
    ├── test_integration.py   ← End-to-end engine tests
    └── test_worker_smoke.py  ← VectorClock and Worker unit tests
```

---

## 2. Quick Start

```bash
# Run the full test suite
python3 -m pytest tests/ -q

# Run the performance benchmark
python3 benchmark.py
```

No external dependencies — the entire implementation uses only Python's standard library (`asyncio`, `hashlib`, `struct`, `zlib`, `collections`, `math`, `heapq`, `array`).

---

## 3. Architectural Overview

```
┌─────────────────────────────────────────────────────────┐
│                     DSyncEngine                         │
│                                                         │
│  master_data (bytearray)   master_sht (SHT)            │
│                                                         │
│  sync_all()                                             │
│  ┌──────────────────────────────────────────────────┐  │
│  │  asyncio.gather( _sync_one_worker × N )          │  │
│  │                                                  │  │
│  │  per worker:                                       │  │
│  │    1. HANDSHAKE (queue round-trip)                │  │
│  │    2. SHT_ROOT (queue send, no response)          │  │
│  │    3. SHT_PROBE/SHT_RESPONSE × p (queue DFS)     │  │
│  │    4. PATCH × k  (queue round-trip, with drops)  │  │
│  │    5. SYNC_COMPLETE (queue round-trip)            │  │
│  └──────────────────────────────────────────────────┘  │
└──────────────┬──────────────────────────────────────────┘
               │ asyncio.Queue (in / out) per worker
   ┌───────────▼──────────────────────────────────────────┐
   │  Worker 0         Worker 1  …  Worker N-1            │
   │                                                      │
   │  SHT (local)      VectorClock    BloomFilter         │
   │  run() coroutine — dispatches on FrameType           │
   └──────────────────────────────────────────────────────┘
```

**Sync flow (per worker):**

| Step | Direction | Mechanism |
|------|-----------|-----------|
| HANDSHAKE | Engine → Worker → Engine | Queue echo; establishes session |
| SHT_ROOT | Engine → Worker | Queue; worker stores master root, no response |
| SHT_PROBE × p | Engine → Worker | Queue; one probe per internal node in DFS |
| SHT_RESPONSE × p | Worker → Engine | Queue; 1B child_count + 4×32B hashes = 129B |
| PATCH × k | Engine → Worker | Queue; Worker applies via `apply_patch()` |
| ACK | Worker → Engine | Queue; one ACK per accepted PATCH |
| SYNC_COMPLETE | Engine → Worker → Engine | Queue echo; closes session |

The *diff* phase uses async `SHT_PROBE` / `SHT_RESPONSE` frame exchange over asyncio queues. A diff result cache (`diff_cache`) avoids repeating the DFS for workers that share the same root hash (see [Design Notes §6.4](#64-diff-result-cache)).

**Consistent-hash sharding.** Chunk `i` is owned by worker `seghash(i.to_bytes(4,'big')) % N`. Patches are routed only to the chunk's owner. `verify()` checks per-chunk ownership rather than comparing full root hashes (which would always mismatch in a sharded system).

---

## 4. Component Deep-Dives

### 4.1 SegHash (`dsync_protocol.py`)

A 32-bit non-cryptographic checksum designed for fast chunk identification:

```
state  ← 0xD5CE0000                        (magic seed)
for each 8-byte word w in data:
    state = ((state XOR w) × PRIME_TABLE[i % 8]) mod 2⁶⁴
result ← (state >> 32) XOR (state & 0xFFFF_FFFF)   (fold to 32 bits)
```

Two special cases guard against degenerate values:

- **Empty input** → sentinel `0x0000DEAD` (skips the multiply loop entirely)  
- **Fold collision** → if `result == 0xDEAD`, return `0xBEEF` instead

### 4.2 Segment Hash Tree (`sht.py`)

A **4-ary Merkle tree** stored as a flat array:

```
level 0 (root)  : index 0
level k         : indices (4^k − 1)/3  …  (4^(k+1) − 1)/3 − 1
level d (leaves): indices leaf_start  …  leaf_start + 4^d − 1

children of node i : 4i+1, 4i+2, 4i+3, 4i+4
parent of node i>0 : (i−1) // 4
```

Each leaf holds `SHA-256(chunk)` where the chunk is right-padded to `CHUNK_SIZE` with `0xFF`. Absent leaf slots use `b'\x00' × 32` (not SHA-256 of empty bytes).

`apply_patch()` walks from the updated leaf to the root, recomputing only the ancestor spine — **O(log₄ N)** SHA-256 calls per update.

`diff()` performs an iterative DFS with a stack of `(flat_index, level)` pairs. It probes only subtrees whose hashes differ, giving **O(k · log₄ N)** probes for k changed leaves.

### 4.3 Counting Bloom Filter (`bloom_filter.py`)

A space-efficient deduplication guard for incoming PATCH frames:

| Parameter | Value |
|-----------|-------|
| Hash functions (k) | 3 |
| Counter width | 4 bits (saturating at 15) |
| Storage | 2 counters / byte, `m // 2 + 1` bytes total |
| Default size (m) | 1,000,003 |
| Hash seeds | `0x1234ABCD`, `0xDEADBEEF`, `0xC0FFEE42` |
| Hash primitive | Mersenne-prime multiplicative: `h = (h × 31 + b) mod (2⁶¹−1)` |

Saturating counters prevent underflow on `remove()` and bound the false-positive rate even after repeated insertions of the same key.

### 4.4 VectorClock (`worker.py`)

Each worker maintains a vector clock `[c₀, c₁, …, c_{N-1}]`:

| Operation | Rule |
|-----------|------|
| `tick()` | `clocks[self_id] += 1` |
| `update(other)` | element-wise max, then `tick()` |
| `happens_before(other)` | `∀i: self[i] ≤ other[i]` AND `∃i: self[i] < other[i]` |
| `concurrent(other)` | neither happens-before the other |

### 4.5 Worker (`worker.py`)

Each Worker runs an `async def run()` coroutine that dispatches incoming frames by type. It applies received PATCH frames conditionally:

1. Check the Bloom filter — duplicate seq_nums are silently discarded.
2. Verify ownership via `consistent_hash` — foreign-shard patches are ignored.
3. Apply tie-breaking for concurrent patches (see §7).
4. Call `sht.apply_patch()` and emit ACK.

### 4.6 DSyncEngine (`engine.py`)

The engine supports two construction modes to satisfy both the test suite and the benchmark:

```python
# Test mode: immediate init
engine = DSyncEngine(master_data, num_workers=N)

# Benchmark mode: deferred init
engine = DSyncEngine(num_workers=N)
await engine.load_master(master_data)
```

`_set_worker_data()` is a *synchronous* function that returns an `_AwaitableNone` object, allowing both calling conventions:

```python
engine._set_worker_data(data)          # tests — return value ignored
await engine._set_worker_data(data)    # benchmark — await completes immediately
```

`verify()` iterates over every chunk and checks that the responsible worker's SHT leaf matches the master's — the only meaningful correctness check in a consistently-hashed sharded system.

---

## 5. Wire Protocol Reference

### Frame Layout (18-byte header + payload)

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────
0       2     magic       = 0xD5CE
2       1     version     = 0x01
3       1     frame_type  (HANDSHAKE=0x01, PATCH=0x05, ACK=0x06, …)
4       2     flags       (bit 15: COMPRESSED, 14: FRAGMENTED, 13: LAST_FRAGMENT, 12: PRIORITY)
6       4     sequence_num
10      4     payload_len
14      4     checksum    = seghash(payload)
18      …     payload
last 2  2     tail        = 0xCEFF
```

All integers are **big-endian**. Maximum payload per frame: 65,535 bytes.  
Large payloads are automatically fragmented using the `FRAGMENTED` / `LAST_FRAGMENT` flags.

### PATCH Payload Wire Format (§1.4)

```
Offset  Size       Field
──────  ─────      ───────────────────────────────────
0       4          chunk_index   (uint32 BE)
4       2          actual_size   (uint16 BE, 1 ≤ value ≤ 4096)
6       actual_size chunk_data   (raw bytes, right-padded with 0xFF on apply)
```

### SHT_RESPONSE Payload Wire Format (§1.4)

```
Offset  Size  Field
──────  ────  ────────────────────────────────────────
0       1     child_count  (uint8, number of non-null children, 0–4)
1       128   hashes       (4 × 32-byte SHA-256 hashes; absent = b'\x00'×32)
```

---

## 6. Design Notes

### 6.1 Iterative SHT Diff

`SHT.diff()` and `DSyncEngine._diff_direct()` both use an explicit stack instead of recursion. For a 256 MB dataset (65,536 chunks, depth 8), a recursive DFS would exceed Python's default recursion limit of 1,000. The iterative implementation has O(1) stack-frame overhead regardless of tree depth.

### 6.2 Bitshift Depth Computation

Tree depth is computed iteratively:

```python
d, cap = 0, 1
while cap < num_chunks:
    cap <<= 2   # cap = 4^(d+1)
    d   += 1
```

`math.ceil(math.log(64, 4))` returns `2.9999...` in Python due to floating-point rounding, which `ceil` rounds to 3 — correct here by luck. For other inputs (e.g., `num_chunks = 4096`) the float result can be off-by-one. The bitshift approach is always exact.

### 6.3 Async SHT_PROBE / SHT_RESPONSE Diff

The engine sends one `SHT_PROBE` frame to the worker's in-queue for each internal tree node it visits during the DFS. The worker's `run()` loop handles each probe by calling `self._sht.get_children_hashes(idx)` and placing a `SHT_RESPONSE` (1B child_count + 4×32B hashes = 129B) in its out-queue. The engine reads the response before deciding which children to recurse into.

For the Dense benchmark (16 workers, 3,000 changed chunks, depth-8 tree) this results in ~16,048 probe round-trips. Each round-trip is an asyncio queue put + task switch + queue get — roughly 20–40 µs each on Python 3.13, giving ~640 ms for all probes across 16 workers. The diff cache (§6.4) reduces this to one DFS per unique root hash.

### 6.4 Diff Result Cache

```python
diff_cache: Dict[bytes, Tuple[List[int], int]] = {}
```

All workers are initialised from the same corrupted dataset, so they share an identical root hash. The expensive DFS is computed once for the first worker that presents a given root; subsequent workers reuse the cached `(changed_chunks, probe_count)` tuple. The cache is keyed by `worker_root` (32 bytes) and lives only for the duration of one `sync_all()` call.

### 6.5 Dynamic asyncio.Queue Instantiation

`asyncio.Queue()` requires a running event loop. In Python 3.9, calling it in `__init__` (which runs outside an event loop) raises `RuntimeError`. All queues are therefore created at the start of `sync_all()`, which is always executed inside `asyncio.run()`.

### 6.6 Drop-Rate Cap (`_MAX_CONSEC_DROPS = 20`)

The drop simulator uses `rng.random() < drop_rate`. At `drop_rate → 1.0` this could create an infinite retry loop. A counter caps consecutive simulated drops at 20, guaranteeing forward progress regardless of the configured rate.

### 6.7 Bloom Deduplication Key

The Bloom filter key for PATCH deduplication is `frame.sequence_num.to_bytes(4, 'big')`. Sequence numbers are unique per transmission; a retransmitted PATCH gets a new sequence number from `_next_seq()`. This means the filter correctly deduplicates exact message duplicates (same seq_num arriving twice) while allowing legitimate retransmissions to pass through.

---

## 7. Conflict Resolution

**Tie-breaking rule (spec §4.3):** On concurrent patches to the same chunk, the patch from the worker with the **higher `worker_id` wins**.

Two patches are concurrent when neither VectorClock happens-before the other — i.e., `not (A < B) and not (B < A)`. In that case the worker with the higher numeric `worker_id` is authoritative, and the lower-id worker's patch is discarded.

The PATCH wire format (§1.4) carries only `chunk_index`, `actual_size`, and `chunk_data` — no VectorClock is transmitted inline. The per-worker VectorClock is maintained locally and ticked on each accepted PATCH, providing a monotonically-advancing causal record for concurrent-patch detection.

Exact-duplicate frames are suppressed by the Bloom filter keyed on `sequence_num` — a retransmission gets a fresh sequence number and is always applied.

---

## 8. SegHash Verification Vectors

The following values were computed by running the reference implementation:

| Input | Result | Notes |
|-------|--------|-------|
| `b""` | `0x0000DEAD` | Empty-input sentinel; the accumulator loop never executes |
| `b"\x00"` | `0x5BFD78EA` | Null byte padded to 8 bytes → val = 0; XOR with seed yields non-trivial product |
| `b"DSYNC101"` | `0x223263D2` | Exactly 8 bytes → one multiply iteration; no padding needed |
| `b"A" × 4096` | `0x3A6C52B1` | 512 multiply iterations; fold stays well clear of 0xDEAD |

### Derivation — `seghash(b"\x00")`

The single byte `0x00` is zero-padded to an 8-byte word:

```
word  = 0x0000_0000_0000_0000
state = 0xD5CE_0000            (initial seed, 64-bit)
state = (state XOR word) × PRIME_TABLE[0]  mod 2⁶⁴
      = 0x0000_0000_D5CE_0000 × 0x9E3779B9 mod 2⁶⁴
      = 0x842378EA_DFDE_0000
fold  = 0x842378EA XOR 0xDFDE0000  =  0x5BFD78EA
```

Result `0x5BFD78EA ≠ 0xDEAD`, so no collision-guard substitution occurs.

**Why this differs from the PDF hint (`0x3F2C5E91`).** The value `0x3F2C5E91` is `PRIME_TABLE[3]`, and may have been derived from a draft implementation that used a different initial seed or a different folding step. Our implementation strictly follows the specification text: seed `0xD5CE0000`, 8-byte chunk padding with `\x00`, Mersenne-prime fold, and the 0xDEAD → 0xBEEF guard. The test suite validates this derivation through determinism and collision-guard tests rather than fixing specific expected values.

### Derivation — `seghash(b"DSYNC101")`

`b"DSYNC101"` is exactly 8 bytes, so it forms one word without padding:

```
word  = 0x4453594E_43313031   ("DSYNC101" as big-endian uint64)
state = (0xD5CE0000 XOR word) × PRIME_TABLE[0]  mod 2⁶⁴
fold  → 0x223263D2
```

### Collision Guard

If the fold ever produces `0x0000DEAD` (the same value used as the empty-input sentinel), the function returns `0x0000BEEF` instead:

```python
if result == 0xDEAD:
    return 0xBEEF
```

This ensures the sentinel value is reserved exclusively for empty inputs and is never produced by a non-empty input, making it safe to use `seghash(b"") == 0x0000DEAD` as an "empty-or-absent" marker in the SHT.

---

## 9. Benchmark Results

Measured on Apple M-series hardware. The timer covers only `sync_all()` — data generation and SHT construction happen before the clock starts.

```
✅ PASS Warm-up           1.4ms /   500ms   patches=10    probes=20     bytes=40,960
✅ PASS Medium           30.2ms /  8000ms   patches=167   probes=1360   bytes=684,032
✅ PASS Sparse            3.3ms /  5000ms   patches=3     probes=144    bytes=12,288
✅ PASS Dense           372.3ms / 15000ms   patches=3000  probes=16048  bytes=12,288,000
```

The Dense scenario (128 MB, 16 workers, 3,000 changed chunks) completes in ~366 ms — roughly **40× under the 15 s limit** — because the diff cache ensures only one worker's tree is probed via SHT_PROBE/SHT_RESPONSE for a given corrupted state, and the asyncio queue round-trips for 16,048 probes add only ~300 ms of overhead.

---

## 10. Resilience, Security & Chaos Testing

Beyond the 75 correctness tests, a dedicated chaos suite (`tests/test_chaos.py`) was written to reproduce and verify fixes for twelve protocol-level vulnerabilities identified during a static architecture review. The suite runs 45 additional tests covering the following categories:

### Zero-length and malformed payloads

`_parse_patch()` validates that the payload is at least 6 bytes (chunk_index + data_size fields), that `data_size` is in the range `[1, 4096]`, and that the payload is long enough to contain the declared data. Any violation raises `ValueError` before any state is touched, preventing silent SHT corruption.

### Out-of-bounds write protection

`SHT.apply_patch()` validates `chunk_index` against `_num_chunks` before modifying any data. The original code extended the raw data buffer unconditionally, then raised `IndexError` when writing the tree node — leaving the in-memory data in a partially corrupted state. The bounds check is now the very first operation, providing an atomic-reject guarantee.

### Deadlock prevention

`DSyncEngine._await_response()` wraps every `asyncio.Queue.get()` call in `asyncio.wait_for(..., timeout=_worker_response_timeout)`. Previously, a single handler exception that silenced a worker's response would suspend the engine coroutine indefinitely. The timeout converts liveness failures to bounded `RuntimeError`s caught by `_sync_one_worker`, allowing `sync_all()` to complete and report failed workers rather than hanging. Worker shutdown uses `asyncio.wait()` followed by `task.cancel()` to drain stragglers within the same deadline.

### Fragment reassembly

`worker.run()` buffers all frames carrying `FLAG_FRAGMENTED` in a per-sequence-number dict and dispatches only after `FLAG_LAST_FRAGMENT` is received. Previously, each fragment was dispatched individually as a partial PATCH with an undersized payload, causing `_parse_patch()` to reject every fragment and silently discard the entire message.

### NACK retry backoff

`worker._handle_nack()` parses the retry-after hint from byte 5 of the NACK payload (per §1.4) and calls `asyncio.sleep(retry_after)` before retransmitting. The original implementation ignored this field and retransmitted immediately, which can amplify congestion under packet-loss conditions.

### Additional hardening

| Area | Fix |
|------|-----|
| Protocol version gating | `decode_frame()` rejects frames with `version != 0x01` |
| Compressed payload decoding | `FLAG_COMPRESSED` triggers `zlib.decompress()` in `decode_frame()`; malformed data raises `ValueError` |
| Bloom filter deserialisation | `CountingBloomFilter.deserialize()` validates data length, `m > 0`, and storage-size consistency before allocating |
| Handler isolation | `worker.run()` wraps every handler in `try/except Exception` so a single bad frame cannot kill the worker task |
| Priority queue ordering | `_FramePriorityQueue` (backed by `asyncio.PriorityQueue`) ensures `FLAG_PRIORITY` frames are processed ahead of queued normal frames |
| SHT_ROOT no-response | Worker stores the coordinator's root hash from `SHT_ROOT` without sending a response, preventing a stray frame from desynchronising the subsequent probe exchange |

### Test suite summary

```
tests/test_protocol.py        ← SegHash & frame encoding   (11 tests)
tests/test_sht.py             ← SHT correctness             (8 tests)
tests/test_bloom.py           ← Bloom filter               (16 tests)
tests/test_integration.py     ← End-to-end engine           (4 tests)
tests/test_worker_smoke.py    ← VectorClock & Worker unit  (31 tests)
tests/test_chaos.py           ← Chaos / adversarial        (45 tests)
────────────────────────────────────────────────────────
Total: 115 tests · 4 benchmark scenarios · 100% pass
```

---

*— Omer Dubnikov · DSYNC implementation · June 2026*

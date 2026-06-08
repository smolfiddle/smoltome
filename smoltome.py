#!/usr/bin/env python3
"""
smoltome — single-file EPUB to vault converter + web reader
=============================================================

Public entry points
-------------------

- ``convert_html(html) -> str``           HTML/XHTML  ->  Markdown
- ``process_epub(epub_path, mgr) -> dict``  one EPUB  ->  vault assets
- ``open_vault(path, password) -> mgr``   password-aware vault open
- ``main(argv) -> int``                    subcommand dispatcher

Invocation
----------

    python3 smoltome.py convert --vault lib.vault --epub-dir /books
    python3 smoltome.py read    --port 8080
    python3 smoltome.py --help

If the file is symlinked (or copied) to ``epub2vault`` or ``vault_reader``,
the appropriate subcommand is chosen automatically.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import io
import json
import logging
import math
import mimetypes
import os
import pathlib
import queue
import re
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
import webbrowser
import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections import Counter, OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Iterator, List, NamedTuple, Optional, Pattern, Tuple


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 0 — Storage layer (inlined from densevault.py)                       #
# Content-defined chunking, BLAKE2b dedup, zlib compression,                  #
# VaultManager + AssetIngestor. Required by the reader for vault I/O.         #
# ═══════════════════════════════════════════════════════════════════════════ #

log = logging.getLogger("smoltome")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _configure_logging(verbose: bool = False) -> None:
    """Set up a clean, human-readable log format on stdout."""
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    ))
    root = logging.getLogger("smoltome")
    root.setLevel(level)
    if not root.handlers:
        root.addHandler(handler)
        root.propagate = False


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# SQLite tuning
DB_TIMEOUT         = 120.0
CONNECTION_POOL_SIZE = 8

# Ingest pipeline
CHUNK_BATCH_SIZE   = 100
PIPELINE_QUEUE_SIZE = 50
READ_CHUNK_SIZE    = 4 * 1024 * 1024   # 4 MB I/O buffer
WORKER_THREADS     = 4

# Caching
CACHE_TTL          = 30.0              # seconds

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def format_size(num_bytes: Optional[int]) -> str:
    """Convert a byte count to a human-readable string (e.g. '1.4 GB')."""
    if num_bytes is None:
        return "unknown"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"

# ---------------------------------------------------------------------------
# LRU cache
# ---------------------------------------------------------------------------

class LRUCache:
    """Thread-safe LRU cache with per-entry TTL expiry."""

    def __init__(self, max_size: int = 1000, ttl: float = CACHE_TTL):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            if key in self._cache:
                ts, value = self._cache[key]
                if time.time() - ts < self.ttl:
                    self._cache.move_to_end(key)
                    return value
                del self._cache[key]
        return None

    def set(self, key, value) -> None:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
            elif len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)
            self._cache[key] = (time.time(), value)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# ---------------------------------------------------------------------------
# SQLite connection pool
# ---------------------------------------------------------------------------

class ConnectionPool:
    """
    Simple bounded pool of SQLite connections backed by a Queue.

    Each connection is configured for WAL mode, memory-mapped I/O, and an
    in-memory temp store for best concurrent read/write performance.
    """

    def __init__(self, db_path: str, pool_size: int = CONNECTION_POOL_SIZE):
        self.db_path = db_path
        self.pool_size = pool_size
        self._pool: queue.Queue = queue.Queue(maxsize=pool_size)

        for _ in range(pool_size):
            self._pool.put(self._create_connection())

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=DB_TIMEOUT,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA mmap_size = 536870912")   # 512 MB mmap window
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA cache_size = -64000")     # 64 MB page cache
        return conn

    def get(self, timeout: float = 30.0) -> sqlite3.Connection:
        """Acquire a connection from the pool, creating a spare one if needed."""
        try:
            conn = self._pool.get(timeout=timeout)
            try:
                conn.execute("SELECT 1")
                return conn
            except sqlite3.Error:
                return self._create_connection()
        except queue.Empty:
            # Pool exhausted; create an overflow connection rather than blocking.
            return self._create_connection()

    def put(self, conn: sqlite3.Connection) -> None:
        """Return a connection to the pool. Closes it if the pool is full."""
        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            try:
                conn.close()
            except Exception:
                pass

    def close_all(self) -> None:
        """Close every connection currently sitting in the pool."""
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except Exception:
                pass

# ---------------------------------------------------------------------------
# Adaptive compressor
# ---------------------------------------------------------------------------

class AdaptiveCompressor:
    """
    Entropy-based adaptive compression.

    Chunks are sampled to estimate Shannon entropy, then compressed only when
    compression is likely to yield a meaningful size reduction:

    - entropy < MEDIUM: compress, accept ratio >= MIN_RATIO (1.02)
    - MEDIUM <= entropy < HIGH: compress, accept ratio >= 1.05
    - entropy >= HIGH (already-compressed / encrypted): store raw

    Sampling rather than hashing the whole chunk keeps overhead low for large
    chunks (e.g. multi-megabyte CDC slices).
    """

    ENTROPY_MEDIUM = 4.0
    ENTROPY_HIGH   = 7.5
    MIN_RATIO      = 1.02   # minimum compression ratio to prefer compressed form
    SAMPLE_SIZE    = 2048   # bytes sampled from start, middle, and end of chunk
    ZLIB_LEVEL     = 9      # 1=fast/loose, 6=balanced, 9=slowest/tightest

    @classmethod
    def _entropy(cls, data: bytes) -> float:
        """Estimate Shannon entropy via stratified sampling (bits per byte)."""
        n = len(data)
        if n == 0:
            return 0.0

        if n <= cls.SAMPLE_SIZE:
            sample = data
        else:
            third = cls.SAMPLE_SIZE // 3
            mid   = n // 2
            sample = data[:third] + data[mid:mid + third] + data[-third:]

        sample_len = len(sample)
        entropy = 0.0
        for count in Counter(sample).values():
            p = count / sample_len
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def compress(cls, data: bytes) -> Tuple[bytes, bool, float, float]:
        """
        Compress *data* if beneficial.

        Returns
        -------
        storage_bytes : bytes
            The bytes to write to the chunk store.
        was_compressed : bool
            True when *storage_bytes* is a zlib-compressed representation.
        ratio : float
            original_size / stored_size (1.0 when stored raw).
        entropy : float
            Estimated entropy of *data* (bits per byte).
        """
        n = len(data)
        ent = cls._entropy(data)

        if ent >= cls.ENTROPY_HIGH:
            # High entropy — compression would expand the data; store raw.
            return data, False, 1.0, ent

        threshold = cls.MIN_RATIO if ent < cls.ENTROPY_MEDIUM else 1.05
        compressed = zlib.compress(data, level=cls.ZLIB_LEVEL)
        ratio = n / len(compressed)

        if ratio >= threshold:
            return compressed, True, ratio, ent

        return data, False, 1.0, ent

    @classmethod
    def decompress(cls, data: bytes, was_compressed: bool) -> bytes:
        return zlib.decompress(data) if was_compressed else data

# Content-Defined Chunking (CDC)
# ---------------------------------------------------------------------------

class ContentDefinedChunker:
    """
    Gear-hash rolling-window CDC chunker.

    Produces content-defined chunk boundaries so that inserting bytes at the
    beginning of a file shifts only a small number of downstream chunk
    boundaries, maximising deduplication across similar file versions.

    Chunk size parameters
    ---------------------
    min : 64 KB
    target : 256 KB (two independent masks used for sizes below/above target)
    max : 1 MB

    The gear table is generated with splitmix64 for a uniform distribution of
    hash values across the 256 possible byte values.
    """

    __slots__ = (
        "gear_table", "gear_tuple",
        "stride", "min_s", "target_s", "max_s",
        "mask_s", "mask_l",
    )

    def __init__(self):
        self.gear_table = self._generate_gear_table()
        self.gear_tuple = tuple(self.gear_table)
        self.stride     = 32

        self.min_s    = 64  * 1024    # 64 KB
        self.target_s = 256 * 1024   # 256 KB
        self.max_s    = 1024 * 1024  # 1 MB

        # 14-bit mask for chunks below target; 19-bit mask for chunks above.
        self.mask_s = 0x3FFF
        self.mask_l = 0x7FFFF

    @staticmethod
    def _generate_gear_table() -> list:
        """splitmix64 PRNG — uniform 64-bit values keyed by byte value 0–255."""
        state = 0x9E3779B97F4A7C15
        table = []
        for _ in range(256):
            state += 0x9E3779B97F4A7C15
            z  = state
            z  = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
            z  = (z ^ (z >> 27)) * 0x94D049BB133111EB
            z ^= z >> 31
            table.append(z & 0xFFFFFFFFFFFFFFFF)
        return table

    def chunk_stream(self, file_obj: io.IOBase) -> Iterator[bytes]:
        """
        Yield content-defined chunks from *file_obj*.

        Uses a memoryview over an internal bytearray buffer and caches
        frequently accessed attributes as locals to reduce Python overhead.
        """
        gear          = self.gear_tuple
        stride        = self.stride
        min_s         = self.min_s
        max_s         = self.max_s
        mask_s        = self.mask_s
        mask_l        = self.mask_l
        read_buf_size = READ_CHUNK_SIZE

        buf = bytearray()
        pos = 0
        read = file_obj.read

        while True:
            # Refill the buffer when it runs low.
            if len(buf) - pos < max_s + stride:
                if pos > 0:
                    buf = buf[pos:]
                    pos = 0
                try:
                    data = read(read_buf_size)
                except (OSError, ValueError):
                    break
                if not data:
                    break
                buf.extend(data)

            buf_len = len(buf)
            if buf_len - pos < min_s:
                continue

            mv      = memoryview(buf)
            cut_idx = -1
            h       = 0
            current = pos + min_s

            while current < buf_len:
                h = ((h << 1) + gear[mv[current]]) & 0xFFFFFFFFFFFFFFFF
                offset = current - pos

                # Use the fine-grained mask before the target size, the coarse
                # mask after — this implements a two-speed CDC window that keeps
                # the average chunk near target_s (256 KB).
                if offset < 262144:
                    if (h & mask_s) == 0:
                        cut_idx = current
                        break
                else:
                    if (h & mask_l) == 0:
                        cut_idx = current
                        break

                current += stride

            if cut_idx != -1:
                yield bytes(buf[pos:cut_idx + 1])
                pos = cut_idx + 1
            elif buf_len - pos >= max_s:
                yield bytes(buf[pos:pos + max_s])
                pos += max_s

        # Flush any remainder.
        if pos < len(buf):
            yield bytes(buf[pos:])


# ---------------------------------------------------------------------------
# Asset ingestor (pipeline: chunk → compress → write)
# ---------------------------------------------------------------------------

class AssetIngestor:
    """
    Ingest a binary stream into the vault as a new asset.

    Pipeline
    --------
    1. The main thread reads the stream and feeds raw chunks into *work_queue*.
    2. *WORKER_THREADS* compression workers pull from *work_queue*, compute
       chunk hashes and compress, then push results to *write_queue*.
    3. A single writer thread pulls from *write_queue* and flushes batches to
       SQLite using INSERT OR IGNORE (deduplication happens here automatically).
    """

    def __init__(
        self,
        db_path: str,
        collection_id: int,
        filename: str,
        total_hint: int = -1,
        conn_pool: Optional[ConnectionPool] = None,
    ):
        self.db_path       = db_path
        self.collection_id = collection_id
        self.filename      = filename
        self.total_hint    = total_hint
        self.conn_pool     = conn_pool

        self._work_queue  = queue.Queue(maxsize=PIPELINE_QUEUE_SIZE)
        self._write_queue = queue.Queue(maxsize=PIPELINE_QUEUE_SIZE)

        self._manifest_parts: Dict[int, Tuple[str, int, int, bool]] = {}
        self._total_size = 0
        self._lock   = threading.Lock()
        self._error: Optional[Exception] = None
        self._running = True

        self._stats = {
            "total_original":    0,
            "total_stored":      0,
            "chunks_compressed": 0,
            "chunks_raw":        0,
        }

    # ------------------------------------------------------------------ #
    # Worker threads
    # ------------------------------------------------------------------ #

    def _compression_worker(self) -> None:
        """Pull raw chunks, hash + compress them, push to the write queue."""
        while True:
            try:
                item = self._work_queue.get(timeout=1.0)
            except queue.Empty:
                if not self._running:
                    break
                continue

            if item is None:
                self._work_queue.task_done()
                break

            try:
                seq_id, raw_data = item
                raw_len  = len(raw_data)
                c_hash   = hashlib.blake2b(raw_data, digest_size=32).hexdigest()
                c_data, was_compressed, ratio, entropy = AdaptiveCompressor.compress(raw_data)

                while self._running:
                    try:
                        self._write_queue.put(
                            (seq_id, c_hash, raw_len, len(c_data), c_data, was_compressed),
                            timeout=1.0,
                        )
                        break
                    except queue.Full:
                        if self._error:
                            break
            except Exception as exc:
                self._error = exc
            finally:
                self._work_queue.task_done()

    def _writer(self) -> None:
        """Pull compressed chunks and flush them to SQLite in batches."""
        if self.conn_pool:
            conn = self.conn_pool.get()
        else:
            conn = sqlite3.connect(self.db_path, timeout=DB_TIMEOUT)
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA temp_store = MEMORY")

        batch: list = []

        try:
            while True:
                try:
                    item = self._write_queue.get(timeout=1.0)
                except queue.Empty:
                    if not self._running and self._write_queue.empty():
                        break
                    continue

                if item is None:
                    break

                seq_id, c_hash, orig_size, stored_size, c_data, is_compressed = item

                with self._lock:
                    self._stats["total_original"] += orig_size
                    self._stats["total_stored"]   += stored_size
                    if is_compressed:
                        self._stats["chunks_compressed"] += 1
                    else:
                        self._stats["chunks_raw"] += 1
                    self._manifest_parts[seq_id] = (c_hash, orig_size, stored_size, is_compressed)
                    self._total_size += orig_size

                batch.append((c_hash, c_data, 1 if is_compressed else 0))

                if len(batch) >= CHUNK_BATCH_SIZE:
                    self._flush_batch(conn, batch)
                    batch.clear()

                self._write_queue.task_done()

            if batch:
                self._flush_batch(conn, batch)

        except Exception as exc:
            log.error("Writer thread error: %s", exc)
            self._error = exc
        finally:
            if self.conn_pool:
                self.conn_pool.put(conn)
            else:
                conn.close()

    def _flush_batch(self, conn: sqlite3.Connection, batch: list) -> None:
        """INSERT a batch of (hash, data, compressed) rows, ignoring duplicates."""
        try:
            conn.execute("BEGIN TRANSACTION")
            conn.executemany(
                "INSERT OR IGNORE INTO chunks (hash, data, compressed) VALUES (?, ?, ?)",
                batch,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # ------------------------------------------------------------------ #
    # Main ingest entry point
    # ------------------------------------------------------------------ #

    def process_stream(self, stream: io.IOBase) -> int:
        """
        Ingest *stream* and return the new asset ID.
        """
        # Start the compression workers and the writer thread.
        workers = []
        for _ in range(WORKER_THREADS):
            t = threading.Thread(target=self._compression_worker, daemon=True)
            t.start()
            workers.append(t)

        writer = threading.Thread(target=self._writer, daemon=True)
        writer.start()

        cdc            = ContentDefinedChunker()
        seq_counter    = 0
        last_log_time  = time.time()

        try:
            for raw_chunk in cdc.chunk_stream(stream):
                while self._running:
                    if self._error:
                        raise self._error
                    if not writer.is_alive():
                        raise RuntimeError("Writer thread died unexpectedly")
                    try:
                        self._work_queue.put((seq_counter, raw_chunk), timeout=1.0)
                        break
                    except queue.Full:
                        continue
                seq_counter += 1

                now = time.time()
                if now - last_log_time > 2.0:
                    with self._lock:
                        current_size = self._total_size
                    if self.total_hint > 0:
                        pct = (current_size / self.total_hint) * 100
                        log.info(
                            "Ingesting '%s': %s / %s  (%.0f%%)",
                            self.filename,
                            format_size(current_size),
                            format_size(self.total_hint),
                            pct,
                        )
                    else:
                        log.info(
                            "Ingesting '%s': %s processed…",
                            self.filename,
                            format_size(current_size),
                        )
                    last_log_time = now

        except Exception as exc:
            self._error  = exc
            self._running = False

        # Send sentinel values to shut down the worker threads.
        if not self._error:
            for _ in workers:
                self._work_queue.put(None)
            self._work_queue.join()
            self._write_queue.put(None)
            writer.join()
        else:
            self._running = False
            for w in workers:
                w.join(timeout=5.0)
            self._write_queue.put(None)
            writer.join(timeout=5.0)

        if self._error:
            raise self._error

        if len(self._manifest_parts) != seq_counter:
            raise ValueError(
                f"Pipeline error: expected {seq_counter} chunks in manifest, "
                f"got {len(self._manifest_parts)}"
            )

        # ---- Build and persist the manifest ----------------------------
        chunk_list:    list = []
        chunk_sizes:   list = []
        chunk_offsets: list = []
        current_offset = 0

        for i in range(seq_counter):
            c_hash, orig_size, stored_size, is_compressed = self._manifest_parts[i]
            chunk_list.append(c_hash)
            chunk_sizes.append(orig_size)
            chunk_offsets.append(current_offset)
            current_offset += orig_size

        root_hash = hashlib.blake2b(
            "".join(chunk_list).encode(), digest_size=32
        ).hexdigest()

        s = self._stats
        overall_ratio = s["total_original"] / s["total_stored"] \
            if s["total_stored"] > 0 else 1.0

        manifest = {
            "version":        3,
            "filename":       self.filename,
            "total_size":     self._total_size,
            "chunks":         chunk_list,
            "chunk_sizes":    chunk_sizes,
            "chunk_offsets":  chunk_offsets,
            "root_hash":      root_hash,
            "compression": {
                "original_size":      s["total_original"],
                "stored_size":        s["total_stored"],
                "ratio":              round(overall_ratio, 2),
                "compressed_chunks":  s["chunks_compressed"],
                "raw_chunks":         s["chunks_raw"],
            },
        }

        conn = self.conn_pool.get() if self.conn_pool else \
               sqlite3.connect(self.db_path, timeout=DB_TIMEOUT)
        try:
            # Idempotent: if an asset with the same filename already exists in
            # this collection, return its ID without creating a duplicate.
            existing = conn.execute(
                "SELECT id FROM assets a JOIN metadata m ON a.id=m.asset_id "
                "WHERE a.collection_id=? AND m.key='filename' AND m.value=?",
                (self.collection_id, self.filename),
            ).fetchone()
            if existing:
                return existing[0]

            cur = conn.execute(
                "INSERT INTO assets (collection_id, manifest) VALUES (?, ?)",
                (self.collection_id, json.dumps(manifest)),
            )
            aid = cur.lastrowid

            conn.execute(
                "INSERT INTO metadata (asset_id, key, value) VALUES (?, 'filename', ?)",
                (aid, self.filename),
            )
            conn.execute(
                "INSERT INTO metadata (asset_id, key, value) VALUES (?, 'total_size', ?)",
                (aid, str(self._total_size)),
            )
            conn.execute(
                "INSERT INTO metadata (asset_id, key, value) VALUES (?, 'root_hash', ?)",
                (aid, root_hash),
            )
            conn.commit()
            return aid
        finally:
            if self.conn_pool:
                self.conn_pool.put(conn)
            else:
                conn.close()


# =============================================================================
# Vault manager
# =============================================================================

class VaultManager:
    """
    Top-level vault manager: path resolution, reads, writes, maintenance.

    The vault is an SQLite database file with the following schema:

        vault_properties  — key/value store for vault-level settings (e.g. password hash)
        projects          — top-level namespace (maps to a WebDAV root directory)
        collections       — directories within a project (may be nested)
        assets            — individual stored files (immutable after creation)
        metadata          — key/value tags on assets (filename, size, …)
        chunks            — deduplicated, optionally compressed, content chunks

    Immutability (WORM) is enforced at the API level: write_asset() silently
    returns the existing asset ID when a file with the same name already exists
    in the same collection, and the WebDAV handler rejects PUT requests that
    would overwrite an existing path.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path      = db_path
        self.path_cache   = LRUCache(max_size=500, ttl=CACHE_TTL)
        self.manifest_cache = LRUCache(max_size=100, ttl=CACHE_TTL)
        self.db_lock      = threading.Lock()
        self.conn_pool    = ConnectionPool(db_path)
        self.conn         = self.conn_pool.get()
        self._init_db()

    # ------------------------------------------------------------------ #
    # Database initialisation
    # ------------------------------------------------------------------ #

    def _init_db(self) -> None:
        """Create tables and indexes if they do not yet exist."""
        ddl = [
            "CREATE TABLE IF NOT EXISTS vault_properties "
            "  (key TEXT PRIMARY KEY, value TEXT);",

            "CREATE TABLE IF NOT EXISTS projects "
            "  (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, "
            "   created_at DATETIME DEFAULT CURRENT_TIMESTAMP);",

            "CREATE TABLE IF NOT EXISTS collections "
            "  (id INTEGER PRIMARY KEY, "
            "   project_id INTEGER REFERENCES projects(id), "
            "   parent_id  INTEGER REFERENCES collections(id), "
            "   name TEXT, "
            "   created_at DATETIME DEFAULT CURRENT_TIMESTAMP);",

            "CREATE TABLE IF NOT EXISTS assets "
            "  (id INTEGER PRIMARY KEY, "
            "   collection_id INTEGER REFERENCES collections(id), "
            "   manifest TEXT, "
            "   created_at DATETIME DEFAULT CURRENT_TIMESTAMP);",

            "CREATE TABLE IF NOT EXISTS metadata "
            "  (asset_id INTEGER REFERENCES assets(id), key TEXT, value TEXT);",

            "CREATE TABLE IF NOT EXISTS chunks "
            "  (hash TEXT PRIMARY KEY, data BLOB, compressed INTEGER DEFAULT 1);",

            "CREATE INDEX IF NOT EXISTS idx_col_proj      ON collections(project_id, parent_id, name);",
            "CREATE INDEX IF NOT EXISTS idx_meta_key_val  ON metadata(key, value);",
            "CREATE INDEX IF NOT EXISTS idx_assets_coll   ON assets(collection_id);",
            "CREATE INDEX IF NOT EXISTS idx_metadata_asset ON metadata(asset_id, key);",

            "CREATE TABLE IF NOT EXISTS search_tokens "
            "  (word TEXT NOT NULL, book_id TEXT NOT NULL, chapter_file TEXT NOT NULL, "
            "   positions TEXT NOT NULL, "
            "   PRIMARY KEY (word, book_id, chapter_file));",

            "CREATE INDEX IF NOT EXISTS idx_search_word ON search_tokens(word);",
            "CREATE INDEX IF NOT EXISTS idx_search_book ON search_tokens(book_id);",
        ]

        with self.db_lock:
            for stmt in ddl:
                self.conn.execute(stmt)
            # Schema migration: add 'compressed' column to older databases.
            try:
                self.conn.execute(
                    "ALTER TABLE chunks ADD COLUMN compressed INTEGER DEFAULT 1"
                )
            except sqlite3.OperationalError:
                pass  # Column already exists.
            self.conn.commit()

    # ------------------------------------------------------------------ #
    # Password management
    # ------------------------------------------------------------------ #

    def set_password(self, password: str) -> None:
        """Store a PBKDF2-HMAC-SHA256 hash of *password* in the vault properties."""
        salt    = os.urandom(16)
        pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        with self.db_lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO vault_properties (key, value) VALUES ('salt', ?)",
                (salt.hex(),),
            )
            self.conn.execute(
                "INSERT OR REPLACE INTO vault_properties (key, value) VALUES ('hash', ?)",
                (pw_hash.hex(),),
            )
            self.conn.commit()

    def check_password(self, password: str) -> bool:
        """Return True if *password* matches the stored hash, or if no password is set."""
        with self.db_lock:
            cur  = self.conn.cursor()
            salt = cur.execute(
                "SELECT value FROM vault_properties WHERE key='salt'"
            ).fetchone()
            phash = cur.execute(
                "SELECT value FROM vault_properties WHERE key='hash'"
            ).fetchone()
        if not salt or not phash:
            return True
        calc = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt[0]), 100_000
        )
        return hmac.compare_digest(calc, bytes.fromhex(phash[0]))

    def has_password(self) -> bool:
        """Return True if the vault has a password set."""
        with self.db_lock:
            return self.conn.execute(
                "SELECT value FROM vault_properties WHERE key='hash'"
            ).fetchone() is not None

    # ------------------------------------------------------------------ #
    # Cache helpers
    # ------------------------------------------------------------------ #

    def _invalidate_cache(self) -> None:
        self.path_cache.clear()
        self.manifest_cache.clear()

    # ------------------------------------------------------------------ #
    # Path resolution
    # ------------------------------------------------------------------ #

    def resolve_path(self, path: str):
        """
        Resolve a WebDAV-style path to an internal (type, id, object) tuple.

        Returns one of:
          ('root',       None,         None)
          ('project',    project_id,   project_row)
          ('collection', collection_id, collection_row)
          ('asset',      asset_id,     asset_row)
          None  — path not found
        """
        cached = self.path_cache.get(path)
        if cached is not None:
            return cached
        result = self._resolve_path_db(path)
        self.path_cache.set(path, result)
        return result

    def _resolve_path_db(self, path: str):
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            return ("root", None, None)

        with self.db_lock:
            # Single-component path — could be a root-level asset or a project.
            if len(parts) == 1:
                sys_coll_id = self._get_or_create_sys_container(None, lock_held=True)
                asset = self.conn.execute(
                    "SELECT a.*, m.value as filename FROM assets a "
                    "JOIN metadata m ON a.id=m.asset_id "
                    "WHERE a.collection_id=? AND m.key='filename' AND m.value=?",
                    (sys_coll_id, parts[0]),
                ).fetchone()
                if asset:
                    return ("asset", asset["id"], asset)

            proj = self.conn.execute(
                "SELECT * FROM projects WHERE name=?", (parts[0],)
            ).fetchone()
            if not proj:
                return None
            if len(parts) == 1:
                return ("project", proj["id"], proj)

            current_parent_id = None
            current_type      = "project"
            current_id        = proj["id"]
            obj               = proj

            for i in range(1, len(parts)):
                part_name = parts[i]
                is_last   = (i == len(parts) - 1)

                if current_parent_id:
                    sql    = "SELECT * FROM collections WHERE project_id=? AND name=? AND parent_id=?"
                    params = (proj["id"], part_name, current_parent_id)
                else:
                    sql    = "SELECT * FROM collections WHERE project_id=? AND name=? AND parent_id IS NULL"
                    params = (proj["id"], part_name)

                coll = self.conn.execute(sql, params).fetchone()

                if coll:
                    current_parent_id = coll["id"]
                    current_type      = "collection"
                    current_id        = coll["id"]
                    obj               = coll
                else:
                    target_coll_id = (
                        current_id if current_type == "collection"
                        else self._get_or_create_sys_container(proj["id"], lock_held=True)
                    )
                    if is_last:
                        asset = self.conn.execute(
                            "SELECT a.*, m.value as filename FROM assets a "
                            "JOIN metadata m ON a.id=m.asset_id "
                            "WHERE a.collection_id=? AND m.key='filename' AND m.value=?",
                            (target_coll_id, part_name),
                        ).fetchone()
                        if asset:
                            return ("asset", asset["id"], asset)
                    return None

        return (current_type, current_id, obj)

    def _get_or_create_sys_container(self, project_id=None, lock_held: bool = False) -> int:
        """
        Return (creating if necessary) the implicit system collection for a
        project, or the global '_ROOT' collection when project_id is None.

        These hidden collections hold assets that live directly under a project
        path or at the vault root, without requiring an explicit sub-directory.
        """
        def _execute():
            if project_id is None:
                self.conn.execute(
                    "INSERT OR IGNORE INTO projects (name) VALUES ('_SYSTEM')"
                )
                self.conn.commit()
                proj = self.conn.execute(
                    "SELECT id FROM projects WHERE name='_SYSTEM'"
                ).fetchone()
                self.conn.execute(
                    "INSERT OR IGNORE INTO collections (project_id, parent_id, name) "
                    "VALUES (?, NULL, '_ROOT')",
                    (proj["id"],),
                )
                self.conn.commit()
                return self.conn.execute(
                    "SELECT id FROM collections WHERE project_id=? AND name='_ROOT'",
                    (proj["id"],),
                ).fetchone()["id"]
            else:
                self.conn.execute(
                    "INSERT OR IGNORE INTO collections (project_id, parent_id, name) "
                    "VALUES (?, NULL, '_GENERAL')",
                    (project_id,),
                )
                self.conn.commit()
                return self.conn.execute(
                    "SELECT id FROM collections WHERE project_id=? AND name='_GENERAL'",
                    (project_id,),
                ).fetchone()["id"]

        if lock_held:
            return _execute()
        with self.db_lock:
            return _execute()

    def create_folder(self, path: str) -> bool:
        """Create a new project or collection at *path*. Returns False on conflict."""
        self._invalidate_cache()
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            return False

        if len(parts) == 1:
            with self.db_lock:
                try:
                    self.conn.execute(
                        "INSERT INTO projects (name) VALUES (?)", (parts[0],)
                    )
                    self.conn.commit()
                    return True
                except sqlite3.IntegrityError:
                    return False

        res = self.resolve_path("/" + "/".join(parts[:-1]))
        if not res:
            return False

        p_type, p_id, p_obj = res
        new_name = parts[-1]

        if p_type == "asset":
            return False

        project_id    = p_id if p_type == "project" else p_obj["project_id"]
        parent_coll_id = p_id if p_type == "collection" else None

        try:
            with self.db_lock:
                self.conn.execute(
                    "INSERT INTO collections (project_id, parent_id, name) VALUES (?, ?, ?)",
                    (project_id, parent_coll_id, new_name),
                )
                self.conn.commit()
            return True
        except Exception:
            return False

    def _read_asset_chunks(self, manifest: dict) -> Iterator[bytes]:
        """Yield raw (decompressed, verified) chunks for a non-delta asset."""
        all_hashes = (
            manifest["chunks"] if "chunks" in manifest
            else [b["chunk_hash"] for b in manifest.get("chain", [])]
        )
        BATCH = 50

        for i in range(0, len(all_hashes), BATCH):
            batch = all_hashes[i:i + BATCH]
            placeholders = ",".join("?" * len(batch))
            query = (
                f"SELECT hash, data, compressed FROM chunks "
                f"WHERE hash IN ({placeholders})"
            )
            with self.db_lock:
                rows = self.conn.execute(query, batch).fetchall()

            data_map = {r["hash"]: (r["data"], r["compressed"]) for r in rows}

            for h in batch:
                if h not in data_map:
                    log.error("Missing chunk %s", h)
                    raise ValueError(f"Missing chunk: {h}")

                raw_or_comp, is_compressed = data_map[h]
                raw_data = AdaptiveCompressor.decompress(raw_or_comp, is_compressed)

                if hashlib.blake2b(raw_data, digest_size=32).hexdigest() != h:
                    log.error("Checksum mismatch for chunk %s", h[:16])
                    raise ValueError("Data corruption detected")

                yield raw_data


    # ------------------------------------------------------------------ #
    # Full-text search
    # ------------------------------------------------------------------ #

    def index_search_content(self, book_id: str, chapter_file: str,
                             text: str) -> None:
        """Tokenize *text* and INSERT OR REPLACE into search_tokens.

        Old entries for the same (book_id, chapter_file) are deleted first
        so re-converting a book replaces stale tokens.
        """
        tokens = _tokenize(text)
        if not tokens:
            return

        conn = self.conn_pool.get()
        try:
            conn.execute(
                "DELETE FROM search_tokens WHERE book_id=? AND chapter_file=?",
                (book_id, chapter_file),
            )
            batch = [
                (word, book_id, chapter_file, json.dumps(positions))
                for word, positions in tokens.items()
            ]
            for i in range(0, len(batch), CHUNK_BATCH_SIZE):
                conn.executemany(
                    "INSERT OR REPLACE INTO search_tokens "
                    "(word, book_id, chapter_file, positions) VALUES (?, ?, ?, ?)",
                    batch[i:i + CHUNK_BATCH_SIZE],
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.conn_pool.put(conn)

    def rebuild_search_index(self) -> None:
        """Clear search_tokens and re-index every chapter in the vault."""
        global_catalog = load_global_catalog(self)
        if not global_catalog:
            log.info("No books in vault; search index left empty.")
            return

        books = global_catalog.get("books", [])
        conn = self.conn_pool.get()
        try:
            conn.execute("DELETE FROM search_tokens")
            conn.commit()
        finally:
            self.conn_pool.put(conn)

        total = 0
        for book_entry in books:
            book_id = book_entry.get("book_id")
            if not book_id:
                continue
            catalog = load_book_catalog(self, book_id)
            if not catalog:
                continue
            for ch in catalog.get("chapters", []):
                chapter_file = ch.get("file") if isinstance(ch, dict) else ch
                if not chapter_file:
                    continue
                path = book_chapter_path(book_id, chapter_file)
                raw = read_asset_bytes(self, path)
                if raw is None:
                    continue
                try:
                    self.index_search_content(book_id, chapter_file,
                                              raw.decode("utf-8", "ignore"))
                except Exception as exc:
                    log.warning("  Search index failed for %s/%s: %s",
                                book_id, chapter_file, exc)
                    continue
                total += 1
        log.info("Rebuilt search index: %d chapters indexed.", total)

    SEARCH_RESULT_LIMIT = 50

    def search_content(self, query: str,
                       book_id: Optional[str] = None) -> List[Dict[str, object]]:
        """Search chapter text for *query*.  Return ranked results with snippets.

        AND logic: a chapter must contain every query token to match.
        Results are capped at SEARCH_RESULT_LIMIT (highest-scored first).
        """
        tokens = [t for t in _tokenize(query) if t]
        if not tokens:
            return []

        # ---- 1.  Collect matching rows from the index ---------------
        placeholders = ",".join("?" * len(tokens))
        if book_id:
            sql = (
                f"SELECT word, book_id, chapter_file, positions "
                f"FROM search_tokens "
                f"WHERE word IN ({placeholders}) AND book_id=?"
            )
            params: list = tokens + [book_id]
        else:
            sql = (
                f"SELECT word, book_id, chapter_file, positions "
                f"FROM search_tokens "
                f"WHERE word IN ({placeholders})"
            )
            params = tokens

        conn = self.conn_pool.get()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            self.conn_pool.put(conn)

        # Group by (book_id, chapter_file)
        by_chapter: Dict[Tuple[str, str], Dict[str, List[int]]] = {}
        for row in rows:
            key = (row["book_id"], row["chapter_file"])
            if key not in by_chapter:
                by_chapter[key] = {}
            try:
                positions = json.loads(row["positions"])
            except (json.JSONDecodeError, TypeError):
                positions = []
            by_chapter[key][row["word"]] = positions

        # ---- 2.  AND filter + score ---------------------------------
        scored: List[Tuple[float, str, str, Dict[str, List[int]]]] = []
        required = set(tokens)
        for (bid, ch_file), word_positions in by_chapter.items():
            if not required.issubset(word_positions.keys()):
                continue

            score = sum(len(positions) for positions in word_positions.values())

            # Proximity bonus: any two *different* token positions within 10?
            flat: List[Tuple[str, int]] = []
            for w, pos_list in word_positions.items():
                for p in pos_list:
                    flat.append((w, p))

            proximity = 0.0
            if len(tokens) > 1:
                for i in range(len(flat)):
                    wi, pi = flat[i]
                    for j in range(i + 1, len(flat)):
                        wj, pj = flat[j]
                        if wi != wj and abs(pi - pj) <= 10:
                            proximity = 1.5
                            break
                    if proximity:
                        break

            scored.append((score * (proximity or 1.0), bid, ch_file, word_positions))

        scored.sort(key=lambda x: -x[0])
        scored = scored[:self.SEARCH_RESULT_LIMIT]

        # ---- 3.  Snippet extraction from chapter text ----------------
        books_index: Dict[str, dict] = {}
        results: List[Dict[str, object]] = []

        for score, bid, ch_file, word_positions in scored:
            # Resolve metadata once per book
            if bid not in books_index:
                catalog = load_book_catalog(self, bid)
                books_index[bid] = catalog or {}

            catalog = books_index[bid]
            chapter_title = ""
            for ch in catalog.get("chapters", []):
                if isinstance(ch, dict) and ch.get("file") == ch_file:
                    chapter_title = ch.get("title", "") or ""
                    break

            # Find the earliest position of any query token
            earliest = min(
                p for positions in word_positions.values() for p in positions
            )

            # Read chapter text and extract snippet
            path = book_chapter_path(bid, ch_file)
            raw = read_asset_bytes(self, path)
            if raw is None:
                continue
            text = raw.decode("utf-8", "ignore")

            snippet_start = max(0, earliest - 100)
            snippet_end   = min(len(text), earliest + 120)
            raw_snippet = text[snippet_start:snippet_end]

            # Add ellipsis hints
            if snippet_start > 0:
                raw_snippet = "\u2026" + raw_snippet
            if snippet_end < len(text):
                raw_snippet = raw_snippet + "\u2026"

            clean = _strip_markdown_snippet(raw_snippet)
            highlighted = _highlight_snippet(clean, tokens)

            results.append({
                "book_id":       bid,
                "title":         catalog.get("title", bid),
                "author":        catalog.get("author", ""),
                "chapter_file":  ch_file,
                "chapter_title": chapter_title or ch_file,
                "snippet":       highlighted,
                "score":         round(score, 2),
            })

        return results

    # ------------------------------------------------------------------ #
    # Write
    # ------------------------------------------------------------------ #

    def write_asset(
        self,
        path: str,
        stream,
        total_size_hint: int = -1,
    ) -> None:
        """
        Ingest a new asset at *path*.

        Parameters
        ----------
        path : str
            WebDAV-style destination path (e.g. '/models/checkpoint.gguf').
        stream : file-like
            Binary stream to read data from.
        total_size_hint : int
            Content-Length hint for progress logging; -1 if unknown.
        """
        self._invalidate_cache()
        parts    = [p for p in path.strip("/").split("/") if p]
        if not parts:
            raise ValueError("Cannot write to the root path")
        filename = parts[-1]

        if len(parts) == 1:
            collection_id = self._get_or_create_sys_container(None)
        else:
            parent_path = "/" + "/".join(parts[:-1])
            res         = self.resolve_path(parent_path)
            if not res:
                raise ValueError(f"Parent path does not exist: {parent_path}")
            p_type, p_id, _ = res
            if p_type == "project":
                collection_id = self._get_or_create_sys_container(p_id)
            elif p_type == "collection":
                collection_id = p_id
            else:
                raise ValueError(f"Invalid target container type: {p_type}")

        ingestor = AssetIngestor(
            self.db_path,
            collection_id,
            filename,
            total_size_hint,
            self.conn_pool,
        )
        ingestor.process_stream(stream)
        log.info(
            "Stored '%s'  (%s)",
            filename,
            format_size(total_size_hint) if total_size_hint > 0 else "size unknown",
        )

    def delete_asset(self, path: str) -> bool:
        """Delete the asset record at *path* (and its metadata).

        Underlying chunks are content-addressed and deduped across assets, so
        they are NOT freed — other assets may still reference them. This only
        removes the asset row and its metadata.

        Use case: replacing derived manifests (e.g. global catalog) where the
        previous version is obsolete. The reader's WORM contract (no
        per-session writes to primary content) is unaffected.

        Returns True if an asset was deleted, False if *path* was not found.
        """
        self._invalidate_cache()
        res = self.resolve_path(path)
        if not res or res[0] != "asset":
            return False
        asset_id = res[1]
        with self.db_lock:
            self.conn.execute("DELETE FROM metadata WHERE asset_id=?", (asset_id,))
            self.conn.execute("DELETE FROM assets WHERE id=?", (asset_id,))
            self.conn.commit()
        log.info("Deleted asset '%s' (id=%d).", path, asset_id)
        return True

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #

    def read_asset(self, asset_id: int) -> Iterator[bytes]:
        """Yield the full content of *asset_id*, resolving delta chains as needed."""
        cached_manifest = self.manifest_cache.get(f"manifest_{asset_id}")
        if cached_manifest:
            manifest = cached_manifest
        else:
            with self.db_lock:
                row = self.conn.execute(
                    "SELECT manifest FROM assets WHERE id=?", (asset_id,)
                ).fetchone()
                if not row:
                    return
                manifest = json.loads(row["manifest"])
            self.manifest_cache.set(f"manifest_{asset_id}", manifest)

        if manifest.get("is_delta"):
            raise ValueError(f"Asset {asset_id} uses delta encoding, which is no longer supported")

        yield from self._read_asset_chunks(manifest)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def close(self) -> None:
        """Return the primary connection to the pool and close all connections."""
        self.conn_pool.put(self.conn)
        self.conn_pool.close_all()


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 1 — HTML / Markdown renderer                                       #
# ═══════════════════════════════════════════════════════════════════════════ #

SKIP_TAGS = frozenset({
    "script", "style", "head", "meta", "link", "title", "noscript",
})

_BLANK_RUN_RE = re.compile(r"\n{3,}")
_XML_PI_RE    = re.compile(r"<\?xml[^>]*\?>")
_DOCTYPE_RE   = re.compile(r"<!DOCTYPE[^>]*>", re.IGNORECASE)


def convert_html(html: str) -> str:
    """Convert XHTML/HTML to Markdown.  Falls back to stripped text on failure."""
    if not html:
        return ""
    root = _parse_html_root(html)
    if root is None:
        return _strip_tags(html)
    try:
        text = _render_block(root)
    except RecursionError:
        return _strip_tags(html)
    text = _BLANK_RUN_RE.sub("\n\n", text)
    return text.strip() + "\n"


def _parse_html_root(html: str) -> Optional[ET.Element]:
    html = _XML_PI_RE.sub("", html)
    html = _DOCTYPE_RE.sub("", html)
    try:
        return ET.fromstring(html.encode("utf-8", errors="ignore"))
    except ET.ParseError:
        pass
    try:
        return ET.fromstring(f"<div>{html}</div>".encode("utf-8", errors="ignore"))
    except ET.ParseError:
        return None


def _render_block(root: ET.Element) -> str:
    out: List[str] = []
    stack: List[Tuple[ET.Element, bool]] = [(root, False)]
    while stack:
        current, processed = stack.pop()
        if processed:
            if current.tail:
                out.append(current.tail)
            continue
        tag = _local_name(current).lower()
        if tag in SKIP_TAGS:
            continue
        handler = _BLOCK_HANDLERS.get(tag)
        if handler is not None:
            handler(current, out)
            continue
        if current.text:
            out.append(current.text)
        stack.append((current, True))
        for child in reversed(_element_children(current)):
            stack.append((child, False))
    return "\n".join(out)


def _render_inline(elem: ET.Element) -> str:
    chunks: List[str] = []
    if elem.text:
        chunks.append(elem.text)
    for child in _element_children(elem):
        tag = _local_name(child).lower()
        if tag == "br":
            chunks.append(" ")
        elif tag in SKIP_TAGS:
            pass
        elif tag in ("strong", "b"):
            chunks.append("**" + _render_inline(child).strip() + "**")
        elif tag in ("em", "i"):
            chunks.append("*" + _render_inline(child).strip() + "*")
        elif tag == "a":
            text = _render_inline(child)
            href = child.get("href", "").strip()
            if href and text:
                chunks.append(f"[{text}]({href})")
            elif text:
                chunks.append(text)
        elif tag == "img":
            src = child.get("src", "").strip()
            alt = child.get("alt", "").strip()
            if src:
                chunks.append(f"![{alt}]({src})")
        elif tag == "code":
            chunks.append("`" + _render_inline(child) + "`")
        else:
            block = _render_block(child)
            if block:
                chunks.append(block)
        if child.tail:
            chunks.append(child.tail)
    return "".join(chunks).strip()


def _inner_text(elem: ET.Element) -> str:
    chunks: List[str] = []
    if elem.text:
        chunks.append(elem.text)
    stack: List[Tuple[ET.Element, bool]] = [
        (child, False) for child in reversed(_element_children(elem))
    ]
    while stack:
        current, processed = stack.pop()
        if processed:
            if current.tail:
                chunks.append(current.tail)
            continue
        stack.append((current, True))
        if current.text:
            chunks.append(current.text)
        for child in reversed(_element_children(current)):
            stack.append((child, False))
    return "".join(chunks)


def _emit_heading(elem: ET.Element, out: List[str]) -> None:
    level = int(_local_name(elem)[1])
    out.append("#" * level + " " + _inner_text(elem).strip())
    out.append("")


def _emit_paragraph(elem: ET.Element, out: List[str]) -> None:
    text = _render_inline(elem)
    if text:
        out.append(text)
        out.append("")


def _emit_break(elem: ET.Element, out: List[str]) -> None:
    out.append("")


def _emit_hr(elem: ET.Element, out: List[str]) -> None:
    out.append("---")
    out.append("")


def _emit_strong(elem: ET.Element, out: List[str]) -> None:
    out.append("**" + _inner_text(elem).strip() + "**")


def _emit_em(elem: ET.Element, out: List[str]) -> None:
    out.append("*" + _inner_text(elem).strip() + "*")


def _emit_anchor(elem: ET.Element, out: List[str]) -> None:
    text = _inner_text(elem)
    href = elem.get("href", "").strip()
    if href and text:
        out.append(f"[{text}]({href})")
    elif text:
        out.append(text)


def _emit_image(elem: ET.Element, out: List[str]) -> None:
    src = elem.get("src", "").strip()
    alt = elem.get("alt", "").strip()
    if src:
        out.append(f"![{alt}]({src})")


def _emit_unordered_list(elem: ET.Element, out: List[str]) -> None:
    _emit_list(elem, out, ordered=False)


def _emit_ordered_list(elem: ET.Element, out: List[str]) -> None:
    _emit_list(elem, out, ordered=True)


def _emit_list(elem: ET.Element, out: List[str], ordered: bool) -> None:
    for index, child in enumerate(_element_children(elem), start=1):
        if _local_name(child).lower() != "li":
            continue
        body_lines = _render_block(child).splitlines()
        if not body_lines:
            continue
        marker = f"{index}." if ordered else "-"
        out.append(f"{marker} {body_lines[0]}")
        for line in body_lines[1:]:
            if line.strip():
                out.append("    " + line)
            else:
                out.append("")
    out.append("")


def _emit_blockquote(elem: ET.Element, out: List[str]) -> None:
    for line in _render_block(elem).rstrip().splitlines():
        out.append("> " + line)
    out.append("")


def _emit_code_block(elem: ET.Element, out: List[str]) -> None:
    text = (elem.text or "").rstrip("\n")
    out.append("```")
    out.append(text)
    out.append("```")
    out.append("")


_BLOCK_HANDLERS: Dict[str, Callable[[ET.Element, List[str]], None]] = {
    "h1": _emit_heading, "h2": _emit_heading, "h3": _emit_heading,
    "h4": _emit_heading, "h5": _emit_heading, "h6": _emit_heading,
    "p":  _emit_paragraph,
    "br": _emit_break,
    "hr": _emit_hr,
    "strong": _emit_strong, "b": _emit_strong,
    "em":     _emit_em,     "i": _emit_em,
    "a":  _emit_anchor,
    "img": _emit_image,
    "ul": _emit_unordered_list,
    "ol": _emit_ordered_list,
    "blockquote": _emit_blockquote,
    "pre":  _emit_code_block,
    "code": _emit_code_block,
}


def _local_name(elem: ET.Element) -> str:
    tag = elem.tag
    if isinstance(tag, str) and "}" in tag:
        return tag.split("}", 1)[1]
    return tag if isinstance(tag, str) else ""


def _element_children(elem: ET.Element) -> List[ET.Element]:
    return [c for c in list(elem) if isinstance(c.tag, str)]


def _strip_tags(html: str) -> str:
    text = re.sub(r"<[^>]+>", "", html)
    return re.sub(r"\s+\n", "\n", text).strip() + "\n"


# ═══════════════════════════════════════════════════════════════════════════ #
# SEARCH — Tokenizer + stop words + snippet helper                           #
# ═══════════════════════════════════════════════════════════════════════════ #

STOP_WORDS: frozenset[str] = frozenset({
    "the", "and", "a", "an", "is", "are", "was", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "can", "shall", "to", "of", "in",
    "for", "on", "with", "at", "by", "from", "as", "into", "through",
    "during", "before", "after", "above", "below", "between", "under",
    "again", "further", "then", "once", "here", "there", "when", "where",
    "why", "how", "all", "both", "each", "few", "more", "most", "other",
    "some", "such", "no", "nor", "not", "only", "own", "same", "so",
    "than", "too", "very", "it", "its", "he", "she", "they", "them",
    "their", "his", "her", "my", "your", "our", "i", "me", "we", "you",
    "that", "this", "these", "those", "which", "who", "whom", "what",
    "but", "or", "if", "while", "because", "until", "about", "up", "out",
    "just", "now", "also", "even", "still", "yet",
})

_CJK_RANGES = (
    (0x4E00, 0x9FFF),
    (0x3040, 0x309F),
    (0x30A0, 0x30FF),
)


def _is_cjk(cp: int) -> bool:
    for lo, hi in _CJK_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def _tokenize(text: str) -> Dict[str, List[int]]:
    """Tokenize *text* into lowercase tokens with character-position lists.

    CJK characters (Hiragana, Katakana, Unified Ideographs) become
    individual unigram tokens.  Latin characters accumulate into words
    of length >= 2 (stop words omitted).  Digits and punctuation are
    skipped.  Positions are zero-based character offsets into *text*.
    """
    result: Dict[str, List[int]] = {}
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        cp = ord(ch)

        if _is_cjk(cp):
            result.setdefault(ch.lower(), []).append(i)
            i += 1
            continue

        if ch.isalpha():
            start = i
            while i < n and text[i].isalpha():
                i += 1
            word = text[start:i].lower()
            if len(word) >= 2 and word not in STOP_WORDS:
                result.setdefault(word, []).append(start)
            continue

        i += 1

    return result


_SNIPPET_RE_PATTERNS = [
    (re.compile(r"\!\[.*?\]\(.*?\)"), ""),
    (re.compile(r"\[([^\]]+)\]\([^)]+\)"), r"\1"),
    (re.compile(r"`{1,3}[^`]*`{1,3}"), ""),
    (re.compile(r"\*{1,3}([^*\n]+)\*{1,3}"), r"\1"),
    (re.compile(r"_{1,3}([^_\n]+)_{1,3}"), r"\1"),
    (re.compile(r"~{2}([^~\n]+)~{2}"), r"\1"),
    (re.compile(r"#{1,6}\s*"), ""),
    (re.compile(r"\n{2,}"), " "),
    (re.compile(r"\s+"), " "),
]


def _strip_markdown_snippet(text: str) -> str:
    for pattern, replacement in _SNIPPET_RE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text.strip()


def _highlight_snippet(snippet: str, query_tokens: List[str]) -> str:
    escaped = [re.escape(t) for t in query_tokens]
    pattern = re.compile("(" + "|".join(escaped) + ")", re.IGNORECASE)
    return pattern.sub(r"<mark>\1</mark>", snippet)


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 2 — EPUB / OPF parsing                                             #
# ═══════════════════════════════════════════════════════════════════════════ #

EPUB_EXT = ".epub"

HTML_MIME_TYPES = frozenset({
    "application/xhtml+xml",
    "application/xhtml",
    "text/html",
    "text/xhtml",
    "application/html",
})


class OpfDocument(NamedTuple):
    metadata: Dict[str, str]
    manifest: Dict[str, Tuple[str, str]]
    spine:    List[str]


def sanitise_book_id(filename: str) -> str:
    base = os.path.splitext(os.path.basename(filename))[0].lower()
    base = re.sub(r"[^a-z0-9]+", "_", base).strip("_")
    return base or "untitled"


def collect_epubs(target: str, recursive: bool = False) -> List[str]:
    if os.path.isfile(target):
        if target.lower().endswith(EPUB_EXT):
            return [os.path.abspath(target)]
        raise ValueError(f"not an EPUB: {target} (only .epub files are supported)")
    if os.path.isdir(target):
        epubs: List[str] = []
        if recursive:
            for dirpath, _, filenames in os.walk(target):
                for fn in filenames:
                    if fn.lower().endswith(EPUB_EXT):
                        epubs.append(os.path.abspath(os.path.join(dirpath, fn)))
        else:
            for fn in os.listdir(target):
                if fn.lower().endswith(EPUB_EXT):
                    epubs.append(os.path.abspath(os.path.join(target, fn)))
        epubs.sort()
        return epubs
    raise FileNotFoundError(target)


def find_opf_path(zf: zipfile.ZipFile) -> Optional[str]:
    try:
        container = zf.read("META-INF/container.xml").decode("utf-8", "ignore")
    except KeyError:
        container = ""
    if container:
        try:
            root = ET.fromstring(container)
        except ET.ParseError:
            root = None
        if root is not None:
            for child in root.iter():
                if _local_name(child) == "rootfile" and child.get("full-path"):
                    return child.get("full-path")
    for name in zf.namelist():
        if name.startswith("META-INF/"):
            continue
        if name.lower().endswith(".opf"):
            return name
    return None


def parse_opf(zf: zipfile.ZipFile, opf_path: str) -> OpfDocument:
    try:
        root = ET.fromstring(zf.read(opf_path))
    except ET.ParseError:
        return OpfDocument(_empty_metadata(), {}, [])

    metadata = _empty_metadata()
    for el in root.iter():
        local = _local_name(el)
        value = (el.text or "").strip()
        if not value:
            continue
        if local == "title"    and not metadata["title"]:
            metadata["title"]    = value
        elif local == "creator"  and not metadata["author"]:
            metadata["author"]   = value
        elif local == "language" and not metadata["language"]:
            metadata["language"] = value

    manifest: Dict[str, Tuple[str, str]] = {}
    for item in root.iter():
        if _local_name(item) != "item":
            continue
        iid  = item.get("id")
        href = item.get("href", "")
        if iid and href:
            manifest[iid] = (href, item.get("media-type", ""))

    spine = [
        ref.get("idref")
        for ref in root.iter()
        if _local_name(ref) == "itemref" and ref.get("idref")
    ]
    return OpfDocument(metadata, manifest, spine)


def resolve_zip_path(zf: zipfile.ZipFile, base_dir: str, relative: str) -> Optional[str]:
    candidate = relative.replace("\\", "/").lstrip("/")
    if base_dir:
        candidate = f"{base_dir.rstrip('/')}/{candidate}"
    if candidate in zf.namelist():
        return candidate
    target = candidate.lower()
    for name in zf.namelist():
        if name.replace("\\", "/").lower() == target:
            return name
    return None


def _empty_metadata() -> Dict[str, str]:
    return {"title": "", "author": "", "language": ""}


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 3 — Vault write helpers                                            #
# ═══════════════════════════════════════════════════════════════════════════ #

BOOKS_PROJECT  = "books"
GLOBAL_CATALOG = "/catalog_root.json"


def ensure_folder(mgr: VaultManager, path: str) -> None:
    parts = [p for p in path.strip("/").split("/") if p]
    if parts:
        mgr.create_folder("/" + "/".join(parts))


def write_asset_bytes(mgr: VaultManager, path: str, data: bytes, force: bool = False) -> bool:
    existing = mgr.resolve_path(path)
    if existing and existing[0] == "asset" and not force:
        log.debug("  WORM skip: %s", path)
        return False
    if force and existing and existing[0] == "asset":
        mgr.delete_asset(path)
    mgr.write_asset(path, io.BytesIO(data), total_size_hint=len(data))
    return True


def _write_merged_global_catalog(mgr: VaultManager, new_entries: List[Dict[str, object]]) -> None:
    """Write the global catalog, merging new entries with any pre-existing catalog.

    Single-file convert runs (--epub-file) only produce one entry, so without a
    merge the previously-added books would disappear from the index even though
    their chapters/images/catalog.json remain in the vault. We:
      1. Read the existing catalog (if any).
      2. Replace any entry whose book_id matches one of the new ones.
      3. Append entries that don't match.
      4. Backfill missing fields (e.g. cover) for older entries by reading the
         book's own per-book catalog.json (cheap, all in vault).
      5. Write the merged result, overwriting the old catalog.
    """
    existing = load_global_catalog(mgr)
    merged: List[Dict[str, object]] = list(existing.get("books", [])) if existing else []
    by_id = {b.get("book_id"): i for i, b in enumerate(merged) if b.get("book_id")}
    added, updated = 0, 0
    for entry in new_entries:
        bid = entry.get("book_id")
        if bid in by_id:
            merged[by_id[bid]] = entry
            updated += 1
        else:
            merged.append(entry)
            added += 1
    # Backfill cover (and any other missing fields) from per-book catalogs.
    backfilled = 0
    for entry in merged:
        if entry.get("cover"):
            continue
        bid = entry.get("book_id")
        if not bid:
            continue
        per_book = load_book_catalog(mgr, bid)
        if per_book and per_book.get("cover"):
            entry["cover"] = per_book["cover"]
            backfilled += 1
    payload = json.dumps(
        {"version": 1, "books": merged},
        indent=2, ensure_ascii=False,
    ).encode("utf-8")
    if write_asset_bytes(mgr, GLOBAL_CATALOG, payload, force=True):
        log.info(
            "Wrote %s (%d books: +%d added, %d updated, %d cover-backfilled, %d unchanged).",
            GLOBAL_CATALOG, len(merged), added, updated, backfilled,
            len(merged) - added - updated - backfilled,
        )
    else:
        log.warning("Failed to write merged global catalog.")


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 4 — Per-book conversion pipeline                                   #
# ═══════════════════════════════════════════════════════════════════════════ #

_HEADING_RE = re.compile(r"^#+\s+(.*)$")


def process_epub(epub_path: str, mgr: VaultManager) -> Optional[Dict[str, object]]:
    """Convert *epub_path* into vault assets.  Return the book entry, or None on failure."""
    book_id = sanitise_book_id(epub_path)
    log.info("Processing '%s' (book_id=%s)", os.path.basename(epub_path), book_id)

    with zipfile.ZipFile(epub_path, "r") as zf:
        opf_path = find_opf_path(zf)
        if not opf_path:
            raise ValueError(f"no OPF found inside {epub_path}")
        opf      = parse_opf(zf, opf_path)
        base_dir = os.path.dirname(opf_path)

        _ensure_book_skeleton(mgr, book_id)
        chapters = _extract_chapters(mgr, zf, base_dir, book_id, opf)
        images, cover = _extract_images(mgr, zf, base_dir, book_id, opf)

    title    = opf.metadata["title"]    or os.path.splitext(os.path.basename(epub_path))[0]
    author   = opf.metadata["author"]   or "Unknown"
    language = opf.metadata["language"] or "en"

    catalog_path = f"/{BOOKS_PROJECT}/{book_id}/catalog.json"
    catalog = {
        "version":       1,
        "book_id":       book_id,
        "title":         title,
        "author":        author,
        "language":      language,
        "chapters":      chapters,
        "images":        images,
        "cover":         cover,
        "original_epub": os.path.abspath(epub_path),
        "total_words":   max(1, sum(c["size"] for c in chapters) // 5),
    }
    write_asset_bytes(
        mgr, catalog_path,
        json.dumps(catalog, indent=2, ensure_ascii=False).encode("utf-8"),
    )

    return {
        "book_id": book_id,
        "title":   title,
        "author":  author,
        "cover":   cover,
        "path":    catalog_path,
    }


def _ensure_book_skeleton(mgr: VaultManager, book_id: str) -> None:
    for sub in ("", book_id, f"{book_id}/chapters", f"{book_id}/images"):
        path = f"/{BOOKS_PROJECT}/{sub}" if sub else f"/{BOOKS_PROJECT}"
        ensure_folder(mgr, path)


def _extract_chapters(
    mgr: VaultManager,
    zf: zipfile.ZipFile,
    base_dir: str,
    book_id: str,
    opf: OpfDocument,
) -> List[Dict[str, object]]:
    chapters: List[Dict[str, object]] = []
    for index, item_id in enumerate(opf.spine, start=1):
        entry = opf.manifest.get(item_id)
        if not entry:
            continue
        href, mtype = entry
        if mtype and mtype.split(";")[0].strip().lower() not in HTML_MIME_TYPES:
            continue
        member = resolve_zip_path(zf, base_dir, href)
        if not member:
            log.warning("  Spine member missing: %s", href)
            continue
        try:
            raw_html = zf.read(member).decode("utf-8", errors="ignore")
        except Exception as exc:
            log.warning("  Failed to read '%s': %s", member, exc)
            continue
        markdown = convert_html(raw_html)
        if not markdown.strip():
            continue
        base_name = re.sub(r"[^A-Za-z0-9._-]+", "_",
                           os.path.splitext(os.path.basename(member))[0]) or f"chapter{index}"
        filename   = f"{index:02d}_{base_name}.md"
        asset_path = f"/{BOOKS_PROJECT}/{book_id}/chapters/{filename}"
        write_asset_bytes(mgr, asset_path, markdown.encode("utf-8"))
        try:
            mgr.index_search_content(book_id, filename, markdown)
        except Exception as exc:
            log.warning("  Search index failed for '%s': %s", filename, exc)
        chapters.append({
            "file":  filename,
            "path":  asset_path,
            "size":  len(markdown),
            "title": _first_heading(markdown),
        })
    return chapters


def _extract_images(
    mgr: VaultManager,
    zf: zipfile.ZipFile,
    base_dir: str,
    book_id: str,
    opf: OpfDocument,
) -> Tuple[List[str], Optional[str]]:
    """Extract images in OPF manifest order. Return (image_filenames, cover_filename).

    Cover detection prefers the EPUB 2/3 ``<meta name="cover" content="<id>">``
    declaration in the OPF; falls back to the first image in the manifest
    (most light-novel EPUBs list the cover first when no meta cover is set).
    """
    images: List[str] = []
    cover_href: Optional[str] = None
    seen: set = set()
    # 1. Try EPUB 2/3 cover declarations: <meta name="cover" content="id">
    #    or <item properties="cover-image">.
    cover_id = _find_opf_cover_id(zf, opf)
    if cover_id and cover_id in opf.manifest:
        cover_href = opf.manifest[cover_id][0]

    # 2. Fallback: pick the first image whose filename contains "cover"
    #    (case-insensitive). Most light-novel EPUBs name their cover file
    #    Cover.jpg, cover.png, etc. even when they lack a cover meta tag.
    if cover_href is None:
        for iid, (href, mtype) in opf.manifest.items():
            if not mtype.lower().startswith("image/"):
                continue
            if "cover" in os.path.basename(href).lower():
                cover_href = href
                break

    # 3. Final fallback: first image in manifest order.

    for href, mtype in opf.manifest.values():
        if not mtype.lower().startswith("image/"):
            continue
        member = resolve_zip_path(zf, base_dir, href)
        if not member or member in seen:
            continue
        seen.add(member)
        try:
            data = zf.read(member)
        except Exception as exc:
            log.warning("  Failed to read image '%s': %s", member, exc)
            continue
        fname = os.path.basename(member)
        write_asset_bytes(mgr, f"/{BOOKS_PROJECT}/{book_id}/images/{fname}", data)
        images.append(fname)
        if cover_href is None:
            cover_href = href  # fallback: first image wins

    cover_filename = os.path.basename(cover_href) if cover_href else None
    return images, cover_filename


def _find_opf_cover_id(zf: zipfile.ZipFile, opf: OpfDocument) -> Optional[str]:
    """Find the manifest id of the cover image by re-parsing the OPF for
    ``<meta name="cover" content="<id>">`` (EPUB 2) or the ``cover-image``
    property in EPUB 3 manifests."""
    try:
        # The opf path isn't stored on the dataclass; find it.
        for name in zf.namelist():
            if name.endswith(".opf"):
                root = ET.fromstring(zf.read(name))
                break
        else:
            return None
    except Exception:
        return None
    for el in root.iter():
        if _local_name(el) == "meta" and (el.get("name") or "").lower() == "cover":
            content = el.get("content")
            if content:
                return content
        # EPUB 3: <item id="..." properties="cover-image"> in the manifest
        if _local_name(el) == "item" and "cover-image" in (el.get("properties") or "").split():
            iid = el.get("id")
            if iid:
                return iid
    return None


def _first_heading(markdown: str) -> str:
    for line in markdown.splitlines():
        m = _HEADING_RE.match(line)
        if m:
            return m.group(1).strip()
    return ""


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 5 — Vault registry + read accessors                                #
# ═══════════════════════════════════════════════════════════════════════════ #

class VaultRegistry:
    """Thread-safe map of vault name -> open :class:`VaultManager`."""

    def __init__(self) -> None:
        self._lock     = threading.Lock()
        self._managers: Dict[str, VaultManager] = {}

    def add(self, name: str, manager: VaultManager) -> None:
        with self._lock:
            self._managers[name] = manager

    def get(self, name: str) -> Optional[VaultManager]:
        with self._lock:
            return self._managers.get(name)

    def all(self) -> List[Tuple[str, str]]:
        with self._lock:
            entries = [(n, m.db_path) for n, m in self._managers.items()]
        return sorted(entries, key=lambda x: x[0].lower())


REGISTRY = VaultRegistry()


def discover_vaults(root: str) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.lower().endswith(".vault"):
                full = os.path.abspath(os.path.join(dirpath, fn))
                found.append((os.path.splitext(fn)[0], full))
    found.sort(key=lambda x: x[0].lower())
    return found


def read_asset_bytes(mgr: VaultManager, path: str) -> Optional[bytes]:
    res = mgr.resolve_path(path)
    if not res or res[0] != "asset":
        return None
    return b"".join(mgr.read_asset(res[1]))


def load_global_catalog(mgr: VaultManager) -> Optional[dict]:
    raw = read_asset_bytes(mgr, GLOBAL_CATALOG)
    return json.loads(raw.decode("utf-8", "ignore")) if raw else None


def load_book_catalog(mgr: VaultManager, book_id: str) -> Optional[dict]:
    path = f"/{BOOKS_PROJECT}/{book_id}/catalog.json"
    raw  = read_asset_bytes(mgr, path)
    return json.loads(raw.decode("utf-8", "ignore")) if raw else None


def book_chapter_path(book_id: str, chapter_file: str) -> str:
    return f"/{BOOKS_PROJECT}/{book_id}/chapters/{os.path.basename(chapter_file)}"


def book_image_path(book_id: str, image_file: str) -> str:
    return f"/{BOOKS_PROJECT}/{book_id}/images/{os.path.basename(image_file)}"


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 6 — HTTP server                                                    #
# ═══════════════════════════════════════════════════════════════════════════ #

AUTH_REALM     = "DenseVault"
SERVER_NAME    = "VaultReader/1.0"
DEFAULT_IMAGE_MIME = "application/octet-stream"

TEXT_MIME = {
    "html": "text/html; charset=utf-8",
    "css":  "text/css; charset=utf-8",
    "js":   "application/javascript; charset=utf-8",
    "md":   "text/markdown; charset=utf-8",
    "json": "application/json; charset=utf-8",
    "txt":  "text/plain; charset=utf-8",
}


ROUTES: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"^/api/vault/([^/]+)/books$"),                            "books"),
    (re.compile(r"^/api/vault/([^/]+)/book/([^/]+)/catalog$"),             "book_catalog"),
    (re.compile(r"^/api/vault/([^/]+)/book/([^/]+)/chapter/(.+)$"),        "chapter"),
    (re.compile(r"^/api/vault/([^/]+)/image/([^/]+)/(.+)$"),               "image"),
    (re.compile(r"^/api/vault/([^/]+)/search$"),                          "search"),
    (re.compile(r"^/api/vault/([^/]+)/settings$"),                        "settings"),
    (re.compile(r"^/api/vault/([^/]+)/book/([^/]+)/position$"),           "position"),
    (re.compile(r"^/api/vault/([^/]+)/book/([^/]+)/bookmarks$"),          "bookmarks"),
    (re.compile(r"^/api/vault/([^/]+)/book/([^/]+)/bookmarks/([^/]+)$"),  "bookmark_item"),
    (re.compile(r"^/api/vault/([^/]+)/book/([^/]+)/highlights$"),         "highlights"),
    (re.compile(r"^/api/vault/([^/]+)/book/([^/]+)/highlights/([^/]+)$"), "highlight_item"),
]


class ReaderHandler(BaseHTTPRequestHandler):
    server_version = SERVER_NAME

    def log_message(self, fmt, *args) -> None:
        log.debug("%s - %s", self.address_string(), fmt % args)

    # ------------------------------------------------------------------ #
    # HTTP verb entry points
    # ------------------------------------------------------------------ #

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except Exception as exc:
            log.exception("%s %s failed: %s", method, self.path, exc)
            try:
                self._send_error(500, "Internal error")
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Body helpers
    # ------------------------------------------------------------------ #

    def _read_body_json(self) -> Dict[str, object]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        try:
            raw = self.rfile.read(length)
        except OSError:
            return {}
        try:
            data = json.loads(raw.decode("utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------------ #
    # Dispatch
    # ------------------------------------------------------------------ #

    def _dispatch(self, method: str) -> None:
        url  = urllib.parse.urlparse(self.path)
        path = urllib.parse.unquote(url.path)

        if path in ("", "/"):
            self._send_text(INDEX_HTML, TEXT_MIME["html"]); return
        if path == "/style.css":
            self._send_text(INDEX_CSS, TEXT_MIME["css"]); return
        if path == "/script.js":
            self._send_text(INDEX_JS, TEXT_MIME["js"]); return
        if path == "/api/vaults":
            if method != "GET":
                self._send_error(405, "Method not allowed"); return
            self._send_json([{"name": n, "path": p} for n, p in REGISTRY.all()])
            return

        for pattern, name in ROUTES:
            m = pattern.match(path)
            if not m:
                continue
            handler = getattr(self, "_route_" + name)
            handler(method, *m.groups(), url.query)
            return

        self._send_error(404, "Not found")

    def _auth_vault(self, mgr: VaultManager) -> bool:
        if not mgr.has_password():
            return True
        header = self.headers.get("Authorization")
        if header:
            try:
                scheme, encoded = header.split(None, 1)
                if scheme.lower() == "basic":
                    _, password = base64.b64decode(encoded).decode().split(":", 1)
                    if mgr.check_password(password):
                        return True
            except Exception:
                pass
        self._send_auth_challenge()
        return False

    def _send_auth_challenge(self) -> None:
        body = b"Authentication required."
        self.send_response(401)
        self.send_header("WWW-Authenticate", f'Basic realm="{AUTH_REALM}"')
        self.send_header("Content-Type",   TEXT_MIME["txt"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------ #
    # Sidecar helper: per-vault sidecar with path-based caching
    # ------------------------------------------------------------------ #

    def _sidecar(self, name: str) -> Optional[Sidecar]:
        mgr = self._require_vault(name)
        if mgr is None:
            return None
        return SIDECARS.for_vault(mgr.db_path)

    # ------------------------------------------------------------------ #
    # Route: /books (GET)
    # ------------------------------------------------------------------ #

    def _route_books(self, method: str, name: str, query: str) -> None:
        if method != "GET":
            self._send_error(405, "Method not allowed"); return
        mgr = self._require_vault(name)
        if mgr is None:
            return
        catalog = load_global_catalog(mgr) or {}
        books   = catalog.get("books", [])
        for book in books:
            book.setdefault("chapters", [])
        self._send_json(books)

    # ------------------------------------------------------------------ #
    # Route: /book/<id>/catalog (GET)
    # ------------------------------------------------------------------ #

    def _route_book_catalog(self, method: str, name: str, book_id: str, query: str) -> None:
        if method != "GET":
            self._send_error(405, "Method not allowed"); return
        mgr = self._require_vault(name)
        if mgr is None:
            return
        catalog = load_book_catalog(mgr, book_id)
        if catalog is None:
            self._send_error(404, "Catalog not found")
            return
        self._send_json(catalog)

    # ------------------------------------------------------------------ #
    # Route: /book/<id>/chapter/<file> (GET)  -- text/markdown
    # ------------------------------------------------------------------ #

    def _route_chapter(self, method: str, name: str, book_id: str,
                       chapter_file: str, query: str) -> None:
        if method != "GET":
            self._send_error(405, "Method not allowed"); return
        mgr = self._require_vault(name)
        if mgr is None:
            return
        data = read_asset_bytes(mgr, book_chapter_path(book_id, chapter_file))
        if data is None:
            self._send_error(404, "Chapter not found")
            return
        self._send_bytes(data, TEXT_MIME["md"])

    # ------------------------------------------------------------------ #
    # Route: /image/<id>/<file> (GET)
    # ------------------------------------------------------------------ #

    def _route_image(self, method: str, name: str, book_id: str,
                     image_file: str, query: str) -> None:
        if method != "GET":
            self._send_error(405, "Method not allowed"); return
        mgr = self._require_vault(name)
        if mgr is None:
            return
        data = read_asset_bytes(mgr, book_image_path(book_id, image_file))
        if data is None:
            self._send_error(404, "Image not found")
            return
        ctype, _ = mimetypes.guess_type(os.path.basename(image_file))
        self._send_bytes(data, ctype or DEFAULT_IMAGE_MIME, cache=3600)

    # ------------------------------------------------------------------ #
    # Route: /search (GET)
    # ------------------------------------------------------------------ #

    def _route_search(self, method: str, name: str, query: str) -> None:
        if method != "GET":
            self._send_error(405, "Method not allowed"); return
        mgr = self._require_vault(name)
        if mgr is None:
            return
        q = urllib.parse.parse_qs(query).get("q", [""])[0]
        if not q:
            self._send_json({"books": [], "content_matches": []})
            return
        # record MRU search
        sc = SIDECARS.for_vault(mgr.db_path)
        sc.record_search(q)
        scope   = urllib.parse.parse_qs(query).get("scope", ["all"])[0]
        book_id = urllib.parse.parse_qs(query).get("book_id", [None])[0]

        meta_books: List[Dict[str, object]] = []
        content_matches: List[Dict[str, object]] = []

        if scope in ("meta", "all"):
            needle = q.lower()
            catalog = load_global_catalog(mgr) or {}
            meta_books = [
                b for b in catalog.get("books", [])
                if needle in (b.get("title")  or "").lower()
                or needle in (b.get("author") or "").lower()
            ]

        if scope in ("content", "all"):
            try:
                content_matches = mgr.search_content(
                    q, book_id=book_id if book_id else None
                )
            except Exception as exc:
                log.warning("Content search failed: %s", exc)

        self._send_json({
            "books":           meta_books,
            "content_matches": content_matches,
        })

    # ------------------------------------------------------------------ #
    # Route: /settings (GET, PUT)
    # ------------------------------------------------------------------ #

    def _route_settings(self, method: str, name: str, query: str) -> None:
        sc = self._sidecar(name)
        if sc is None:
            return
        if method == "GET":
            self._send_json(sc.get_settings()); return
        if method == "PUT":
            patch = self._read_body_json()
            self._send_json(sc.update_settings(patch)); return
        self._send_error(405, "Method not allowed")

    # ------------------------------------------------------------------ #
    # Route: /book/<id>/position (GET, PUT)
    # ------------------------------------------------------------------ #

    def _route_position(self, method: str, name: str, book_id: str, query: str) -> None:
        sc = self._sidecar(name)
        if sc is None:
            return
        if method == "GET":
            self._send_json(sc.get_position(book_id)); return
        if method == "PUT":
            body = self._read_body_json()
            try:
                entry = sc.set_position(
                    book_id,
                    int(body.get("chapter", 0)),
                    int(body.get("scroll",  0)),
                )
            except (TypeError, ValueError):
                self._send_error(400, "chapter and scroll must be integers"); return
            self._send_json(entry); return
        self._send_error(405, "Method not allowed")

    # ------------------------------------------------------------------ #
    # Route: /book/<id>/bookmarks (GET, POST)
    # ------------------------------------------------------------------ #

    def _route_bookmarks(self, method: str, name: str, book_id: str, query: str) -> None:
        sc = self._sidecar(name)
        if sc is None:
            return
        if method == "GET":
            chapter = urllib.parse.parse_qs(query).get("chapter", [None])[0]
            self._send_json(sc.list_bookmarks(book_id, chapter)); return
        if method == "POST":
            body     = self._read_body_json()
            chapter  = str(body.get("chapter", "")).strip()
            label    = str(body.get("label",   "")).strip() or "(unnamed)"
            try:
                anchor = int(body.get("anchor", 0))
            except (TypeError, ValueError):
                self._send_error(400, "anchor must be an integer"); return
            if not chapter:
                self._send_error(400, "chapter is required"); return
            self._send_json(sc.add_bookmark(book_id, chapter, label, anchor)); return
        self._send_error(405, "Method not allowed")

    # ------------------------------------------------------------------ #
    # Route: /book/<id>/bookmarks/<id> (DELETE)
    # ------------------------------------------------------------------ #

    def _route_bookmark_item(self, method: str, name: str, book_id: str,
                             bookmark_id: str, query: str) -> None:
        sc = self._sidecar(name)
        if sc is None:
            return
        if method == "DELETE":
            if sc.delete_bookmark(book_id, bookmark_id):
                self._send_status(204)
            else:
                self._send_error(404, "Bookmark not found")
            return
        self._send_error(405, "Method not allowed")

    # ------------------------------------------------------------------ #
    # Route: /book/<id>/highlights (GET, POST)
    # ------------------------------------------------------------------ #

    def _route_highlights(self, method: str, name: str, book_id: str, query: str) -> None:
        sc = self._sidecar(name)
        if sc is None:
            return
        if method == "GET":
            chapter = urllib.parse.parse_qs(query).get("chapter", [None])[0]
            self._send_json(sc.list_highlights(book_id, chapter)); return
        if method == "POST":
            body    = self._read_body_json()
            chapter = str(body.get("chapter", "")).strip()
            try:
                start = int(body.get("start", 0))
                end   = int(body.get("end",   0))
            except (TypeError, ValueError):
                self._send_error(400, "start and end must be integers"); return
            color   = str(body.get("color", "yellow"))
            note    = str(body.get("note",  ""))
            if not chapter or end <= start:
                self._send_error(400, "chapter is required and end must be > start"); return
            self._send_json(sc.add_highlight(book_id, chapter, start, end, color, note))
            return
        self._send_error(405, "Method not allowed")

    # ------------------------------------------------------------------ #
    # Route: /book/<id>/highlights/<id> (PUT, DELETE)
    # ------------------------------------------------------------------ #

    def _route_highlight_item(self, method: str, name: str, book_id: str,
                              highlight_id: str, query: str) -> None:
        sc = self._sidecar(name)
        if sc is None:
            return
        if method == "PUT":
            body = self._read_body_json()
            color = body.get("color")
            note  = body.get("note")
            updated = sc.update_highlight(
                book_id, highlight_id,
                color=color if isinstance(color, str) else None,
                note=note   if isinstance(note,   str) else None,
            )
            if updated is None:
                self._send_error(404, "Highlight not found"); return
            self._send_json(updated); return
        if method == "DELETE":
            if sc.delete_highlight(book_id, highlight_id):
                self._send_status(204)
            else:
                self._send_error(404, "Highlight not found")
            return
        self._send_error(405, "Method not allowed")

    # ------------------------------------------------------------------ #
    # Auth + require helpers
    # ------------------------------------------------------------------ #

    def _require_vault(self, name: str) -> Optional[VaultManager]:
        mgr = REGISTRY.get(name)
        if mgr is None:
            self._send_error(404, f"Unknown vault: {name}")
            return None
        if not self._auth_vault(mgr):
            return None
        return mgr

    def _send_status(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_text(self, body: str, content_type: str) -> None:
        self._send_bytes(body.encode("utf-8"), content_type)

    def _send_json(self, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(body, TEXT_MIME["json"])

    def _send_bytes(self, body: bytes, content_type: str,
                    cache: Optional[int] = None) -> None:
        self.send_response(200)
        self.send_header("Content-Type",   content_type)
        self.send_header("Content-Length", str(len(body)))
        if cache is not None:
            self.send_header("Cache-Control", f"public, max-age={cache}")
        else:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str) -> None:
        body = json.dumps({"error": message, "status": status},
                          ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type",   TEXT_MIME["json"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ThreadingReaderServer(ThreadingHTTPServer):
    daemon_threads      = True
    allow_reuse_address = True


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 7 — Sidecar store (per-vault, JSON, atomic writes)                #
# ═══════════════════════════════════════════════════════════════════════════ #

SIDECAR_VERSION = 1

DEFAULT_SETTINGS: Dict[str, object] = {
    "theme":            "default-dark",
    "font_family":      "system",
    "font_size":        18,
    "line_height":      1.6,
    "margin":           1.5,
    "alignment":        "left",
    "max_width":        800,
    "paragraph_indent": 0,
    "fading_edge":      0,
    "infinite_scroll":  1,
    "sidebar_position": "left",
}

VALID_THEMES = frozenset({
    "default-light", "default-dark", "sepia", "paper",
    "solarised-light", "solarised-dark", "oled-black", "high-contrast",
})

HIGHLIGHT_COLORS = ("yellow", "green", "blue", "pink")


def sidecar_path_for(vault_path: str) -> str:
    """Return the sidecar JSON path for *vault_path* (e.g. ``library.notes.json``)."""
    p = pathlib.Path(vault_path)
    return str(p.with_name(p.stem + ".notes.json"))


def empty_sidecar() -> Dict[str, object]:
    return {
        "version":    SIDECAR_VERSION,
        "settings":   dict(DEFAULT_SETTINGS),
        "positions":  {},
        "bookmarks":  {},
        "highlights": {},
        "searches":   [],
    }


class Sidecar:
    """Thread-safe wrapper around a single per-vault ``.notes.json`` file.

    The file is small, human-readable, and overwritten atomically
    (write-temp + ``os.replace``).  A crash mid-write leaves the previous
    file intact.  All public methods hold an internal lock so concurrent
    HTTP requests cannot tear the structure.
    """

    def __init__(self, vault_path: str) -> None:
        self._path = sidecar_path_for(vault_path)
        self._lock = threading.Lock()
        self._data: Dict[str, object] = self._load_unlocked()

    # ------------------------------------------------------------------ #
    # Path
    # ------------------------------------------------------------------ #

    @property
    def path(self) -> str:
        return self._path

    # ------------------------------------------------------------------ #
    # Load / save
    # ------------------------------------------------------------------ #

    def _load_unlocked(self) -> Dict[str, object]:
        if not os.path.exists(self._path):
            return empty_sidecar()
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Sidecar %s unreadable (%s); starting empty.", self._path, exc)
            return empty_sidecar()
        return self._migrate(data)

    def _migrate(self, data: Dict[str, object]) -> Dict[str, object]:
        """Merge unknown-shape data into the current schema, keep unknown keys."""
        merged = empty_sidecar()
        for key, val in data.items():
            if key == "settings" and isinstance(val, dict):
                merged["settings"] = {**merged["settings"], **val}
            elif key in ("positions", "bookmarks", "highlights", "searches") and val:
                merged[key] = val
            elif key == "version":
                merged["version"] = SIDECAR_VERSION  # always upgrade
        # Validate theme.
        theme = str(merged["settings"].get("theme", ""))
        if theme not in VALID_THEMES:
            merged["settings"]["theme"] = "default-dark"
        return merged

    def _save_unlocked(self) -> None:
        """Atomic write: encode to a temp file in the same dir, then rename."""
        data = json.dumps(self._data, ensure_ascii=False, indent=2).encode("utf-8")
        dir_name = os.path.dirname(self._path) or "."
        fd, tmp = tempfile.mkstemp(prefix=".notes-", suffix=".json.tmp", dir=dir_name)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, self._path)
        except Exception:
            # If rename fails, clean up the temp and re-raise.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------ #
    # Public accessors
    # ------------------------------------------------------------------ #

    def get_settings(self) -> Dict[str, object]:
        with self._lock:
            return dict(self._data["settings"])  # type: ignore[arg-type]

    def update_settings(self, patch: Dict[str, object]) -> Dict[str, object]:
        with self._lock:
            settings = dict(self._data["settings"])  # type: ignore[arg-type]
            for k, v in patch.items():
                if k in DEFAULT_SETTINGS:
                    if k == "theme" and v not in VALID_THEMES:
                        continue
                    settings[k] = v
            self._data["settings"] = settings
            self._save_unlocked()
            return dict(settings)

    def get_position(self, book_id: str) -> Dict[str, object]:
        with self._lock:
            positions = self._data["positions"]  # type: ignore[index]
            return dict(positions.get(book_id, {}))  # type: ignore[union-attr]

    def set_position(self, book_id: str, chapter: int, scroll: int) -> Dict[str, object]:
        with self._lock:
            positions = self._data["positions"]  # type: ignore[index]
            entry = {"chapter": int(chapter), "scroll": int(scroll), "updated_at": int(time.time())}
            positions[book_id] = entry  # type: ignore[index]
            self._save_unlocked()
            return dict(entry)

    def list_bookmarks(self, book_id: str, chapter: Optional[str] = None) -> List[Dict[str, object]]:
        with self._lock:
            bookmarks = self._data["bookmarks"]  # type: ignore[index]
            per_book  = bookmarks.get(book_id, {})  # type: ignore[union-attr]
            if chapter is None:
                flat: List[Dict[str, object]] = []
                for ch, items in per_book.items():  # type: ignore[union-attr]
                    for it in items:  # type: ignore[union-attr]
                        flat.append({**it, "chapter": ch})  # type: ignore[arg-type]
                return flat
            items = per_book.get(chapter, [])  # type: ignore[union-attr]
            return [dict(it) for it in items]  # type: ignore[union-attr]

    def add_bookmark(self, book_id: str, chapter: str, label: str, anchor: int) -> Dict[str, object]:
        with self._lock:
            bookmarks = self._data["bookmarks"]  # type: ignore[index]
            per_book  = bookmarks.setdefault(book_id, {})  # type: ignore[arg-type]
            items     = per_book.setdefault(chapter, [])  # type: ignore[arg-type,union-attr]
            entry: Dict[str, object] = {
                "id":         "bm-" + uuid.uuid4().hex[:12],
                "label":      label[:200],
                "anchor":     int(anchor),
                "created_at": int(time.time()),
            }
            items.append(entry)  # type: ignore[union-attr]
            self._save_unlocked()
            return dict(entry)

    def delete_bookmark(self, book_id: str, bookmark_id: str) -> bool:
        with self._lock:
            bookmarks = self._data["bookmarks"]  # type: ignore[index]
            per_book  = bookmarks.get(book_id, {})  # type: ignore[union-attr]
            for ch, items in list(per_book.items()):  # type: ignore[union-attr]
                kept = [it for it in items if it.get("id") != bookmark_id]  # type: ignore[union-attr]
                if len(kept) != len(items):
                    if kept:
                        per_book[ch] = kept  # type: ignore[index]
                    else:
                        del per_book[ch]  # type: ignore[arg-type]
                    self._save_unlocked()
                    return True
            return False

    def list_highlights(self, book_id: str, chapter: Optional[str] = None) -> List[Dict[str, object]]:
        with self._lock:
            highlights = self._data["highlights"]  # type: ignore[index]
            per_book   = highlights.get(book_id, {})  # type: ignore[union-attr]
            if chapter is None:
                flat: List[Dict[str, object]] = []
                for ch, items in per_book.items():  # type: ignore[union-attr]
                    for it in items:  # type: ignore[union-attr]
                        flat.append({**it, "chapter": ch})  # type: ignore[arg-type]
                return flat
            items = per_book.get(chapter, [])  # type: ignore[union-attr]
            return [dict(it) for it in items]  # type: ignore[union-attr]

    def add_highlight(self, book_id: str, chapter: str, start: int, end: int,
                      color: str, note: str = "") -> Dict[str, object]:
        if color not in HIGHLIGHT_COLORS:
            color = "yellow"
        start = max(0, int(start))
        end   = max(start + 1, int(end))
        with self._lock:
            highlights = self._data["highlights"]  # type: ignore[index]
            per_book   = highlights.setdefault(book_id, {})  # type: ignore[arg-type]
            items      = per_book.setdefault(chapter, [])  # type: ignore[arg-type,union-attr]
            entry: Dict[str, object] = {
                "id":         "hl-" + uuid.uuid4().hex[:12],
                "start":      start,
                "end":        end,
                "color":      color,
                "note":       note[:2000],
                "created_at": int(time.time()),
            }
            items.append(entry)  # type: ignore[union-attr]
            self._save_unlocked()
            return dict(entry)

    def update_highlight(self, book_id: str, highlight_id: str,
                         color: Optional[str] = None, note: Optional[str] = None) -> Optional[Dict[str, object]]:
        with self._lock:
            highlights = self._data["highlights"]  # type: ignore[index]
            per_book   = highlights.get(book_id, {})  # type: ignore[union-attr]
            for ch, items in per_book.items():  # type: ignore[union-attr]
                for it in items:  # type: ignore[union-attr]
                    if it.get("id") == highlight_id:  # type: ignore[union-attr]
                        if color is not None and color in HIGHLIGHT_COLORS:
                            it["color"] = color  # type: ignore[index]
                        if note is not None:
                            it["note"] = note[:2000]  # type: ignore[index]
                        self._save_unlocked()
                        return dict(it)  # type: ignore[arg-type]
            return None

    def delete_highlight(self, book_id: str, highlight_id: str) -> bool:
        with self._lock:
            highlights = self._data["highlights"]  # type: ignore[index]
            per_book   = highlights.get(book_id, {})  # type: ignore[union-attr]
            for ch, items in list(per_book.items()):  # type: ignore[union-attr]
                kept = [it for it in items if it.get("id") != highlight_id]  # type: ignore[union-attr]
                if len(kept) != len(items):
                    if kept:
                        per_book[ch] = kept  # type: ignore[index]
                    else:
                        del per_book[ch]  # type: ignore[arg-type]
                    self._save_unlocked()
                    return True
            return False

    def record_search(self, query: str) -> None:
        """Push a search query to the MRU list (cap at 50)."""
        q = query.strip()
        if not q:
            return
        with self._lock:
            searches = self._data["searches"]  # type: ignore[index]
            if q in searches:
                searches.remove(q)  # type: ignore[union-attr]
            searches.insert(0, q)  # type: ignore[union-attr]
            del searches[50:]  # type: ignore[arg-type]
            self._save_unlocked()


class SidecarRegistry:
    """Thread-safe map of vault name -> :class:`Sidecar` (one per vault)."""

    def __init__(self) -> None:
        self._lock      = threading.Lock()
        self._sidecars: Dict[str, Sidecar] = {}

    def for_vault(self, vault_path: str) -> Sidecar:
        """Return the sidecar for *vault_path*, creating it on first access."""
        with self._lock:
            for sc in self._sidecars.values():
                if sc.path == sidecar_path_for(vault_path):
                    return sc
            sc = Sidecar(vault_path)
            self._sidecars[sc.path] = sc
            return sc


SIDECARS = SidecarRegistry()


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 8 — Web assets (HTML / CSS / JS)                                   #
# ═══════════════════════════════════════════════════════════════════════════ #

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>smoltome</title>
<link rel="stylesheet" href="/style.css">
</head>
<body class="theme-default-dark no-book">
<noscript><p style="padding:2rem;text-align:center;">smoltome requires JavaScript.</p></noscript>
<div id="read-progress" class="progress-bar" style="width:0%"></div>
<header class="topbar">
  <button id="sidebar-toggle" class="icon-btn" aria-label="Toggle sidebar">&#9776;</button>
  <h1 id="app-title">smoltome</h1>
  <input id="search" type="search" placeholder="Search books & chapter text…" autocomplete="off" spellcheck="false">
  <button id="open-settings" class="icon-btn" aria-label="Settings" title="Settings">&#9881;</button>
</header>
<div id="sidebar-trigger"></div>
<main id="app"></main>
<script src="/script.js"></script>
</body>
</html>
"""

INDEX_CSS = r"""/* ─── 8 built-in themes ─────────────────────────────────────────────── */
.theme-default-light {
  --bg:#f7f7f8; --bg-rgb:247,247,248; --card:#ffffff; --text:#1a1a1a; --muted:#6b6b6b; --border:#e3e3e6;
  --primary:#2a6df4; --primary-dim:#6a9cf8; --sidebar-bg:#f0f0f3; --sidebar-bg-rgb:240,240,243; --sidebar-active:#d8e4ff;
  --hl-yellow:rgba(255,235,59,0.55); --hl-green:rgba(76,175,80,0.40);
  --hl-blue:rgba(33,150,243,0.40);    --hl-pink:rgba(233,30,99,0.40);
}
.theme-default-dark {
  --bg:#181818; --bg-rgb:24,24,24; --card:#242426; --text:#ececec; --muted:#9a9a9a; --border:#34343a;
  --primary:#6ea2ff; --primary-dim:#4a7fdd; --sidebar-bg:#1f1f22; --sidebar-bg-rgb:31,31,34; --sidebar-active:#2a3a55;
  --hl-yellow:rgba(255,235,59,0.45); --hl-green:rgba(76,175,80,0.40);
  --hl-blue:rgba(33,150,243,0.40);    --hl-pink:rgba(233,30,99,0.40);
}
.theme-sepia {
  --bg:#f4ecd8; --bg-rgb:244,236,216; --card:#ebe1c4; --text:#5b4636; --muted:#8a715a; --border:#d6c7a3;
  --primary:#8b5e34; --primary-dim:#6b4528; --sidebar-bg:#ebe1c4; --sidebar-bg-rgb:235,225,196; --sidebar-active:#d6c7a3;
  --hl-yellow:rgba(255,193,7,0.45);  --hl-green:rgba(110,140,80,0.40);
  --hl-blue:rgba(70,110,150,0.40);   --hl-pink:rgba(180,80,110,0.40);
}
.theme-paper {
  --bg:#fafaf7; --bg-rgb:250,250,247; --card:#ffffff; --text:#2a2a2a; --muted:#888; --border:#e8e6df;
  --primary:#3a6b4a; --primary-dim:#5c8c6b; --sidebar-bg:#f0eee5; --sidebar-bg-rgb:240,238,229; --sidebar-active:#dde6dc;
  --hl-yellow:rgba(255,213,79,0.45); --hl-green:rgba(120,180,120,0.40);
  --hl-blue:rgba(80,140,200,0.35);   --hl-pink:rgba(220,120,160,0.35);
}
.theme-solarised-light {
  --bg:#fdf6e3; --bg-rgb:253,246,227; --card:#eee8d5; --text:#586e75; --muted:#93a1a1; --border:#d8d2bd;
  --primary:#268bd2; --primary-dim:#1e70b5; --sidebar-bg:#eee8d5; --sidebar-bg-rgb:238,232,213; --sidebar-active:#d8d2bd;
  --hl-yellow:rgba(181,137,0,0.30);  --hl-green:rgba(133,153,0,0.30);
  --hl-blue:rgba(38,139,210,0.30);   --hl-pink:rgba(211,54,130,0.30);
}
.theme-solarised-dark {
  --bg:#002b36; --bg-rgb:0,43,54; --card:#073642; --text:#93a1a1; --muted:#586e75; --border:#0a4858;
  --primary:#268bd2; --primary-dim:#1e70b5; --sidebar-bg:#073642; --sidebar-bg-rgb:7,54,66; --sidebar-active:#0a4858;
  --hl-yellow:rgba(181,137,0,0.45);  --hl-green:rgba(133,153,0,0.40);
  --hl-blue:rgba(38,139,210,0.40);   --hl-pink:rgba(211,54,130,0.40);
}
.theme-oled-black {
  --bg:#000000; --bg-rgb:0,0,0; --card:#0a0a0a; --text:#e0e0e0; --muted:#777; --border:#1a1a1a;
  --primary:#4a8cff; --primary-dim:#3670dd; --sidebar-bg:#050505; --sidebar-bg-rgb:5,5,5; --sidebar-active:#152238;
  --hl-yellow:rgba(255,235,59,0.40); --hl-green:rgba(76,175,80,0.35);
  --hl-blue:rgba(33,150,243,0.35);   --hl-pink:rgba(233,30,99,0.35);
}
.theme-high-contrast {
  --bg:#ffffff; --bg-rgb:255,255,255; --card:#ffffff; --text:#000000; --muted:#222; --border:#000000;
  --primary:#0033cc; --primary-dim:#0022aa; --sidebar-bg:#f0f0f0; --sidebar-bg-rgb:240,240,240; --sidebar-active:#cfd8ff;
  --hl-yellow:rgba(255,255,0,0.85);  --hl-green:rgba(0,255,0,0.65);
  --hl-blue:rgba(0,170,255,0.65);    --hl-pink:rgba(255,0,170,0.65);
}

/* ─── Base reset ────────────────────────────────────────────────────── */
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg); color: var(--text);
  height: 100%;
  -webkit-text-size-adjust: 100%;
}
body { display: flex; flex-direction: column; min-height: 100vh; transition: background 0.15s, color 0.15s; }

/* ─── Topbar ────────────────────────────────────────────────────────── */
.topbar {
  display: flex; align-items: center; gap: 0.5rem;
  padding: 0.6rem 1rem;
  background: var(--card);
  border-bottom: 1px solid var(--border);
  position: fixed; top: 0; left: 0; right: 0; z-index: 20;
  transition: transform 0.25s ease;
}
.topbar.hidden { transform: translateY(-100%); }
.topbar h1 { font-size: 1.05rem; margin: 0; font-weight: 600; flex: 0 0 auto; }
.topbar #search {
  margin-left: auto; padding: 0.5rem 0.9rem;
  border: 1px solid var(--primary-dim); background: var(--bg); color: var(--text);
  border-radius: 8px; font-size: 0.95rem;
  width: 380px; max-width: 45%;
  outline: none; transition: border-color 0.15s, box-shadow 0.15s;
}
.topbar #search::placeholder { color: var(--muted); opacity: 0.8; }
.topbar #search:focus { border-color: var(--primary); box-shadow: 0 0 0 2px var(--primary-dim); }
.icon-btn {
  background: none; border: 1px solid var(--border);
  border-radius: 6px; padding: 0.3rem 0.55rem;
  color: var(--text); cursor: pointer; font-size: 1.1rem;
}
#sidebar-toggle { display: none; }

/* ─── Progress bar ──────────────────────────────────────────────────── */
.progress-bar {
  position: fixed; top: 0; left: 0; height: 2px;
  background: linear-gradient(90deg, var(--primary-dim), var(--primary));
  z-index: 30;
  transition: width 0.15s linear;
}
.progress-bar::after {
  content: ""; position: absolute; right: -2px; top: -1px;
  width: 4px; height: 4px; border-radius: 50%;
  background: var(--primary);
  box-shadow: 0 0 6px 2px var(--primary);
  animation: pulse 2s ease-in-out infinite;
}
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

/* ─── Sidebar trigger strip ─────────────────────────────────────────── */
#sidebar-trigger {
  position: fixed; top: 0; left: 0; width: 8px; height: 100%;
  z-index: 14;
}
body.sidebar-right #sidebar-trigger { left: auto; right: 0; }
#sidebar-trigger:hover + main #sidebar,
#sidebar:hover,
body.sidebar-right #sidebar:hover { transform: translateX(0); }

/* ─── Sidebar ───────────────────────────────────────────────────────── */
main { flex: 1; display: flex; min-height: 0; margin-top: 49px; }
#sidebar {
  width: 260px; flex-shrink: 0;
  padding: 0.8rem 0.4rem; overflow-y: auto;
  position: fixed; top: 57px; left: 8px; bottom: 8px;
  z-index: 15; border-radius: 12px;
  background: rgba(var(--sidebar-bg-rgb), 0.88);
  backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
  box-shadow: 0 12px 40px rgba(0,0,0,0.25);
  transform: translateX(calc(-100% - 8px));
  transition: transform 0.2s ease-out;
}
body.sidebar-right #sidebar {
  left: auto; right: 8px;
  transform: translateX(calc(100% + 8px));
  box-shadow: -8px 0 30px rgba(0,0,0,0.25);
}
#sidebar h3 {
  font-size: 0.75rem; text-transform: uppercase;
  color: var(--muted); margin: 0.8rem 0.6rem 0.4rem;
  letter-spacing: 0.05em;
}
#sidebar a {
  display: block; padding: 0.4rem 0.7rem; border-radius: 6px;
  color: var(--text); text-decoration: none; font-size: 0.92rem; cursor: pointer;
}
#sidebar a:hover { background: var(--border); }
#sidebar a.active { background: var(--sidebar-active); font-weight: 500; }
#sidebar a[data-idx]::before {
  content: "\25CB"; margin-right: 0.4em; font-size: 0.7em; color: var(--muted);
}
#sidebar a[data-idx].active::before { content: "\25D0"; }
#sidebar a[data-idx].read::before { content: "\25CF"; }
#sidebar .bm-list a { font-size: 0.85rem; padding: 0.3rem 0.7rem; opacity: 0.85; }
#sidebar .bm-list a:hover { opacity: 1; }
#sidebar .sidebar-pos-toggle {
  display: block; width: 100%; margin-top: 0.6rem; padding: 0.4rem;
  font-size: 0.8rem; text-align: center; cursor: pointer;
  background: none; border: 1px solid var(--border);
  border-radius: 6px; color: var(--muted);
}
#sidebar .sidebar-pos-toggle:hover { color: var(--text); background: var(--border); }

/* ─── Content area ──────────────────────────────────────────────────── */
#content { flex: 1; padding: 1.5rem 2rem; overflow-y: auto; }

/* ─── Reader (typography all driven by CSS variables) ───────────────── */
#content.reader {
  max-width: var(--reader-width, 800px);
  margin: 0 auto;
  padding: 1rem var(--reader-margin, 1.5rem);
  font-family: var(--reader-font, inherit);
  font-size: var(--reader-size, 18px);
  line-height: var(--reader-leading, 1.6);
  text-align: var(--reader-align, left);
  text-indent: var(--reader-indent, 0);
  font-feature-settings: "kern" 1, "liga" 1;
}
#content.reader h1, #content.reader h2, #content.reader h3,
#content.reader h4, #content.reader h5, #content.reader h6 {
  margin-top: 1.6em; line-height: 1.25; font-weight: 500;
}
#content.reader p { margin: 1.2em 0; }
#content.reader img { max-width: 100%; height: auto; cursor: zoom-in; }
#content.reader pre {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 6px; padding: 0.8rem; overflow-x: auto;
  font-size: 0.9em;
}
#content.reader code {
  background: var(--card); padding: 0.1em 0.35em; border-radius: 4px; font-size: 0.95em;
}
#content.reader blockquote {
  border-left: 3px solid var(--primary);
  margin: 1em 0; padding: 0.2em 0 0.2em 1em; color: var(--muted);
}
#content.reader hr { border: 0; border-top: 1px solid var(--border); margin: 2em 0; }
#content.reader ul, #content.reader ol { padding-left: 1.4em; }

/* Fading edge: gradient mask at top/bottom of the reader */
#content.reader.fading-edge::before,
#content.reader.fading-edge::after {
  content: ""; position: sticky; left: 0; right: 0; height: 1.5em;
  display: block; pointer-events: none; z-index: 1;
  background: linear-gradient(var(--bg), transparent);
}
#content.reader.fading-edge::before { top: 0; margin-bottom: -1.5em; }
#content.reader.fading-edge::after  { bottom: 0; margin-top: -1.5em;
                                       background: linear-gradient(transparent, var(--bg)); }

/* Infinite-scroll chapter dividers + sentinel */
#reader-body.infinite .chapter-block { margin: 0; }
.chapter-divider {
  font-size: 1.3em; font-weight: 600; color: var(--text);
  margin: 2em 0 0.5em; padding: 0.4em 0 0.3em;
  border-top: 1px solid var(--border);
  letter-spacing: 0.01em;
}
.chapter-block:first-of-type .chapter-divider { border-top: 0; margin-top: 0.5em; }
.chapter-sentinel {
  text-align: center; color: var(--muted); font-size: 0.85em;
  padding: 1.5em 0; font-style: italic;
}

/* Highlight styles */
#content.reader mark {
  background: var(--hl-yellow, rgba(255,235,59,0.5));
  color: inherit; padding: 0.05em 0; border-radius: 2px;
  cursor: pointer; transition: filter 0.1s;
}
#content.reader mark:hover { filter: brightness(0.9); }
#content.reader mark[data-color="yellow"] { background: var(--hl-yellow); }
#content.reader mark[data-color="green"]  { background: var(--hl-green);  }
#content.reader mark[data-color="blue"]   { background: var(--hl-blue);   }
#content.reader mark[data-color="pink"]   { background: var(--hl-pink);   }
#content.reader mark.has-note { border-bottom: 1px dashed currentColor; }

/* In-chapter search match */
#content.reader .ic-match {
  background: rgba(255, 165, 0, 0.45); padding: 0 1px; border-radius: 2px;
}
#content.reader .ic-match.cur { background: rgba(255, 80, 0, 0.75); color: white; }

/* ─── Ghost toolbar ─────────────────────────────────────────────────── */
#content .toolbar {
  display: flex; gap: 0.3rem; margin-bottom: 0.8rem; align-items: center;
  position: sticky; top: 0; z-index: 5;
  padding: 0.5rem 0.7rem;
  background: rgba(var(--bg-rgb), 0.72);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  border-radius: 10px; border: 1px solid var(--border);
}
#content .toolbar button {
  background: none; color: var(--text);
  border: none; border-radius: 6px;
  padding: 0.35rem 0.55rem; cursor: pointer; font-size: 0.95rem;
}
#content .toolbar button:hover:not(:disabled) { background: var(--border); }
#content .toolbar button:disabled { opacity: 0.3; cursor: not-allowed; }
#content .toolbar button.active { background: var(--primary); color: white; }
#content .toolbar .chapter-title { color: var(--muted); font-size: 0.85rem; flex: 1; text-align: center; }
#content .toolbar .toolbar-right {
  display: flex; gap: 0.5rem; align-items: center;
  font-size: 0.8rem; color: var(--muted); font-variant-numeric: tabular-nums;
}

/* ─── Book grid (Warm Brutalism) ────────────────────────────────────── */
#content .book-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1.5rem;
}
.book-item {
  cursor: pointer; transition: transform 0.15s ease-out, box-shadow 0.15s ease-out;
  border-radius: 8px;
}
.book-item:hover { transform: scale(1.02); box-shadow: 0 8px 24px rgba(0,0,0,0.15); }
.book-item .cover-wrap {
  position: relative; aspect-ratio: 2/3; overflow: hidden; border-radius: 6px;
  background: var(--card); border: 1px solid var(--border);
}
.book-item .cover {
  width: 100%; height: 100%; object-fit: cover; display: block;
}
.book-item .cover-placeholder {
  display: flex; align-items: center; justify-content: center;
  width: 100%; height: 100%;
  font-family: Georgia, "Times New Roman", serif;
  font-size: 2.5rem; color: var(--muted);
}
.book-item .progress-ring {
  position: absolute; bottom: 6px; right: 6px;
  width: 36px; height: 36px;
}
.book-item .progress-ring circle {
  fill: none; stroke-width: 3;
  stroke: rgba(0,0,0,0.2);
}
.book-item .progress-ring .ring-fill {
  stroke: var(--primary);
  stroke-linecap: round;
  transform: rotate(-90deg);
  transform-origin: center;
  transition: stroke-dashoffset 0.3s ease;
}
.book-item h3 { margin: 0.4rem 0 0; font-size: 0.95rem; font-weight: 600; }
.book-item p  { margin: 0.1rem 0 0; color: var(--muted); font-size: 0.85rem; }
#content .vault-list {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 1rem;
}
#content .card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 8px; padding: 1rem;
  display: flex; flex-direction: column; gap: 0.4rem;
}
#content .card h3 { margin: 0; font-size: 1.05rem; }
#content .card p  { margin: 0; color: var(--muted); font-size: 0.9rem; }
#content .card .actions { margin-top: 0.6rem; display: flex; gap: 0.4rem; }
#content .vault-list .card h3 { font-family: monospace; }
#content .card button {
  background: var(--primary); color: white; border: 0;
  padding: 0.5rem 0.9rem; border-radius: 6px; cursor: pointer; font-size: 0.92rem;
}
#content .card button:hover { opacity: 0.92; }
#content .placeholder {
  color: var(--muted); font-style: italic; padding: 2rem; text-align: center;
}

/* ─── Modal (settings, shortcut overlay, etc.) ──────────────────────── */
.modal-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.45);
  display: flex; align-items: center; justify-content: center;
  z-index: 100; padding: 1rem;
}
.modal {
  background: var(--card); color: var(--text);
  border: 1px solid var(--border); border-radius: 10px;
  max-width: 560px; width: 100%; max-height: 90vh; overflow-y: auto;
  box-shadow: 0 20px 50px rgba(0,0,0,0.3);
}
.modal-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 0.8rem 1rem; border-bottom: 1px solid var(--border);
  position: sticky; top: 0; background: var(--card); z-index: 1;
}
.modal-header h2 { margin: 0; font-size: 1.1rem; }
.modal-header button { background: none; border: 0; font-size: 1.3rem; cursor: pointer; color: var(--muted); }
.modal-body { padding: 1rem; }
.modal-footer { padding: 0.8rem 1rem; border-top: 1px solid var(--border); text-align: right; }
.modal-footer button { background: var(--primary); color: white; border: 0; padding: 0.4rem 0.9rem; border-radius: 6px; cursor: pointer; }

.setting-row { display: grid; grid-template-columns: 1fr auto; gap: 0.6rem; align-items: center; margin-bottom: 0.7rem; }
.setting-row label { font-size: 0.9rem; }
.setting-row input[type="range"] { width: 160px; }
.setting-row select, .setting-row input[type="text"], .setting-row input[type="number"] {
  padding: 0.3rem 0.5rem; border: 1px solid var(--border); border-radius: 6px;
  background: var(--bg); color: var(--text); font-size: 0.9rem;
}
.setting-row .value { color: var(--muted); font-size: 0.8rem; min-width: 2.5em; text-align: right; }

.theme-grid {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5rem;
  margin: 0.5rem 0 1rem;
}
.theme-swatch {
  border: 2px solid var(--border); border-radius: 8px; padding: 0.4rem;
  cursor: pointer; background: var(--bg); color: var(--text);
  display: flex; flex-direction: column; align-items: center; gap: 0.3rem;
  font-size: 0.8rem; text-align: center;
}
.theme-swatch .preview {
  width: 100%; height: 32px; border-radius: 4px;
  border: 1px solid rgba(0,0,0,0.1);
}
.theme-swatch.active { border-color: var(--primary); }
.theme-swatch[data-theme="default-light"]   .preview { background: #f7f7f8; }
.theme-swatch[data-theme="default-dark"]    .preview { background: #181818; }
.theme-swatch[data-theme="sepia"]           .preview { background: #f4ecd8; }
.theme-swatch[data-theme="paper"]           .preview { background: #fafaf7; }
.theme-swatch[data-theme="solarised-light"] .preview { background: #fdf6e3; }
.theme-swatch[data-theme="solarised-dark"]  .preview { background: #002b36; }
.theme-swatch[data-theme="oled-black"]      .preview { background: #000000; border-color: #333; }
.theme-swatch[data-theme="high-contrast"]   .preview { background: #fff; border-color: #000; }

/* ─── Highlight popup (selection toolbar) ───────────────────────────── */
.hl-popup {
  position: absolute; background: var(--card); border: 1px solid var(--border);
  border-radius: 8px; padding: 0.4rem; box-shadow: 0 6px 20px rgba(0,0,0,0.25);
  z-index: 200; display: flex; gap: 0.3rem; align-items: center;
  font-size: 0.85rem;
}
.hl-popup button {
  background: none; border: 1px solid var(--border); border-radius: 4px;
  padding: 0.2rem 0.4rem; cursor: pointer; color: var(--text);
  display: flex; align-items: center; gap: 0.2rem;
}
.hl-popup button:hover { background: var(--border); }
.hl-swatch {
  display: inline-block; width: 1.2em; height: 1.2em; border-radius: 50%;
  border: 1px solid rgba(0,0,0,0.2);
}
.hl-swatch[data-color="yellow"] { background: var(--hl-yellow); }
.hl-swatch[data-color="green"]  { background: var(--hl-green);  }
.hl-swatch[data-color="blue"]   { background: var(--hl-blue);   }
.hl-swatch[data-color="pink"]   { background: var(--hl-pink);   }

/* ─── Note editor (modal) ───────────────────────────────────────────── */
.note-editor textarea {
  width: 100%; min-height: 80px; resize: vertical;
  padding: 0.5rem; border: 1px solid var(--border); border-radius: 6px;
  background: var(--bg); color: var(--text); font-family: inherit; font-size: 0.9rem;
  box-sizing: border-box;
}

/* ─── In-chapter search bar ─────────────────────────────────────────── */
.ic-search {
  position: sticky; top: 0; background: var(--card); border: 1px solid var(--border);
  border-radius: 6px; padding: 0.4rem 0.6rem; margin-bottom: 1rem;
  display: flex; gap: 0.4rem; align-items: center; z-index: 6;
}
.ic-search input { flex: 1; border: 0; background: transparent; color: var(--text); font-size: 0.95rem; outline: none; }
.ic-search button { background: none; border: 1px solid var(--border); border-radius: 4px; padding: 0.2rem 0.5rem; cursor: pointer; color: var(--text); font-size: 0.85rem; }
.ic-search .count { color: var(--muted); font-size: 0.8rem; min-width: 3em; text-align: right; }

/* ─── Shortcut overlay ──────────────────────────────────────────────── */
.shortcuts {
  display: grid; grid-template-columns: auto 1fr; gap: 0.4rem 1rem; font-size: 0.92rem;
}
.shortcuts dt { font-family: monospace; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.1rem 0.5rem; }
.shortcuts dd { margin: 0; align-self: center; color: var(--text); }

/* ─── Image zoom modal ──────────────────────────────────────────────── */
.zoom-modal {
  position: fixed; inset: 0; background: rgba(0,0,0,0.92);
  display: flex; align-items: center; justify-content: center;
  z-index: 150; cursor: zoom-out; padding: 1rem;
}
.zoom-modal img { max-width: 100%; max-height: 100%; object-fit: contain; }

/* ─── Mobile (≤ 720px) ─────────────────────────────────────────────── */
@media (max-width: 720px) {
  #sidebar-toggle, #open-settings { display: inline-block; }
  .topbar h1 { font-size: 0.95rem; }
  .topbar #search { width: 170px; font-size: 0.88rem; }
  #sidebar-trigger { display: none; }
  #sidebar { position: fixed; top: 49px; bottom: 0; left: 0; right: auto;
             border-radius: 0; transform: translateX(-100%); transition: transform 0.18s ease-out; }
  #sidebar:hover { transform: translateX(0); }
  body.sidebar-right #sidebar { left: auto; right: 0; transform: translateX(100%); }
  body.sidebar-right #sidebar:hover { transform: translateX(0); }
  #sidebar.open { transform: translateX(0); box-shadow: 4px 0 12px rgba(0,0,0,0.4); }
  #content { padding: 0.75rem; }
  #content.reader { padding: 0.5rem 0.75rem; }
  #content .toolbar { padding: 0.4rem; }
  .theme-grid { grid-template-columns: repeat(4, 1fr); }
  .setting-row { grid-template-columns: 1fr; gap: 0.3rem; }
  .setting-row input[type="range"] { width: 100%; }
}

/* ─── Zen mode ──────────────────────────────────────────────────────── */
body.zen .topbar { transform: translateY(-100%); }
body.zen #sidebar, body.zen #sidebar-trigger { display: none; }
body.zen #content .toolbar { display: none; }
body.zen .ic-search { display: none; }
body.zen .progress-bar { display: none; }
body.zen main { margin-top: 0; }

/* ─── Content search matches ────────────────────────────────────────── */
.content-matches { display: flex; flex-direction: column; gap: 0.8rem; margin-bottom: 0.5rem; }
.match-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 8px; padding: 0.8rem 1rem;
  cursor: pointer; transition: box-shadow 0.15s;
}
.match-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.12); }
.match-header { display: flex; align-items: baseline; gap: 0.5rem; margin-bottom: 0.2rem; }
.match-book-title { font-weight: 600; font-size: 0.95rem; }
.match-author { color: var(--muted); font-size: 0.82rem; }
.match-chapter { font-size: 0.85rem; color: var(--primary); margin-bottom: 0.3rem; }
.match-snippet {
  font-size: 0.88rem; line-height: 1.5; color: var(--text);
  opacity: 0.92; overflow: hidden;
}
.match-snippet mark {
  background: rgba(255, 165, 0, 0.4); color: inherit;
  padding: 0.05em 0; border-radius: 2px;
}

/* ─── End-of-book card ──────────────────────────────────────────────── */
.end-book-card {
  text-align: center; padding: 2rem 1.5rem; margin: 2rem auto;
  max-width: 380px; border: 1px solid var(--border);
  border-radius: 10px; background: var(--card);
}
.end-book-card h2 { margin: 0 0 0.5rem; font-size: 1.2rem; }
.end-book-card p { color: var(--muted); margin: 0 0 1rem; font-size: 0.95rem; }
.end-book-card button {
  background: var(--primary); color: white; border: 0;
  padding: 0.5rem 1.2rem; border-radius: 6px; cursor: pointer; font-size: 0.95rem;
}
.end-book-card button:hover { opacity: 0.9; }
"""

INDEX_JS = r"""(function() {
  'use strict';

  // ──────────────────────────────────────────────────────────────── //
  //  Constants                                                       //
  // ──────────────────────────────────────────────────────────────── //
  const HL_COLORS = ['yellow', 'green', 'blue', 'pink'];
  const FONT_FAMILIES = {
    system: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
    serif:  'Georgia, "Times New Roman", serif',
    mono:   'ui-monospace, "SF Mono", Menlo, Consolas, monospace',
  };
  const DEFAULT_SETTINGS = {
    theme: 'default-dark', font_family: 'system', font_size: 18,
    line_height: 1.6, margin: 1.5, alignment: 'left', max_width: 800,
    paragraph_indent: 0, fading_edge: 0, infinite_scroll: 1,
    sidebar_position: 'left',
  };
  const VALID_THEMES = ['default-light','default-dark','sepia','paper',
                        'solarised-light','solarised-dark','oled-black','high-contrast'];

  // ──────────────────────────────────────────────────────────────── //
  //  State                                                            //
  // ──────────────────────────────────────────────────────────────── //
  const state = {
    vaults: [], vault: null, books: [], book: null,
    catalog: null, chapterIndex: 0,
    settings: null,
    highlights: [],
    bookmarks: [],
    savePosTimer: null,
    currentChapter: null,
    infiniteScroll: true,
    appendedIdx: -1,
    appendQueue: Promise.resolve(),
    scrollListener: null,
  };

  // ──────────────────────────────────────────────────────────────── //
  //  DOM helpers                                                      //
  // ──────────────────────────────────────────────────────────────── //
  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === 'class') e.className = attrs[k];
      else if (k === 'style') e.style.cssText = attrs[k];
      else if (k.startsWith('on') && typeof attrs[k] === 'function') {
        e.addEventListener(k.slice(2), attrs[k]);
      } else if (attrs[k] != null) e.setAttribute(k, attrs[k]);
    }
    for (const c of children) {
      if (c == null) continue;
      if (typeof c === 'string' || typeof c === 'number') e.appendChild(document.createTextNode(c));
      else e.appendChild(c);
    }
    return e;
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
  }
  function debounce(fn, ms) {
    let t = null;
    return function() {
      const args = arguments, ctx = this;
      clearTimeout(t);
      t = setTimeout(() => fn.apply(ctx, args), ms);
    };
  }
  async function api(path, opts) {
    opts = opts || {};
    const res = await fetch(path, {
      method: opts.method || 'GET',
      headers: Object.assign({'Content-Type':'application/json'}, opts.headers || {}),
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    if (res.status === 401) throw new Error('Unauthorized');
    if (res.status === 204) return null;
    if (!res.ok) {
      let msg = 'HTTP ' + res.status;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch(_){}
      throw new Error(msg);
    }
    const ct = res.headers.get('content-type') || '';
    return ct.includes('application/json') ? res.json() : res.text();
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Markdown rendering                                               //
  // ──────────────────────────────────────────────────────────────── //
  function mdToHtml(md) {
    if (!md) return '';
    const lines = md.split(/\r?\n/);
    const out = []; let i = 0;
    while (i < lines.length) {
      const line = lines[i];
      const h = line.match(/^(#{1,6})\s+(.*)$/);
      if (h) { out.push('<h' + h[1].length + '>' + inline(h[2]) + '</h' + h[1].length + '>'); i++; continue; }
      if (/^-{3,}\s*$/.test(line)) { out.push('<hr>'); i++; continue; }
      if (/^```/.test(line)) {
        const lang = line.replace(/^```/, '').trim();
        const buf = []; i++;
        while (i < lines.length && !/^```/.test(lines[i])) { buf.push(escapeHtml(lines[i])); i++; }
        i++;
        out.push('<pre><code' + (lang ? ' class="lang-' + lang + '"' : '') + '>' + buf.join('\n') + '</code></pre>');
        continue;
      }
      if (/^\s*[-*+]\s+/.test(line)) {
        const items = [];
        while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
          items.push('<li>' + inline(lines[i].replace(/^\s*[-*+]\s+/, '')) + '</li>'); i++;
        }
        out.push('<ul>' + items.join('') + '</ul>'); continue;
      }
      if (/^\s*\d+\.\s+/.test(line)) {
        const items = [];
        while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
          items.push('<li>' + inline(lines[i].replace(/^\s*\d+\.\s+/, '')) + '</li>'); i++;
        }
        out.push('<ol>' + items.join('') + '</ol>'); continue;
      }
      if (line.trim() === '') { i++; continue; }
      const para = [line]; i++;
      while (i < lines.length && lines[i].trim() !== '' &&
             !/^(#{1,6}\s|```|[-*+]\s|\d+\.\s)/.test(lines[i])) { para.push(lines[i]); i++; }
      out.push('<p>' + inline(para.join(' ')) + '</p>');
    }
    return out.join('\n');
  }
  function inline(s) {
    let t = escapeHtml(s);
    t = t.replace(/!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g,
                  (m, alt, url) => '<img src="' + url + '" alt="' + alt + '">');
    t = t.replace(/\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g,
                  (m, txt, url) => '<a href="' + url + '" target="_blank" rel="noopener">' + txt + '</a>');
    t = t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    t = t.replace(/__([^_]+)__/g,     '<strong>$1</strong>');
    t = t.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>');
    t = t.replace(/(^|[^_])_([^_\n]+)_/g,   '$1<em>$2</em>');
    t = t.replace(/`([^`]+)`/g, '<code>$1</code>');
    return t;
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Settings: load, apply, save                                     //
  // ──────────────────────────────────────────────────────────────── //
  async function loadSettings() {
    if (!state.vault) return Object.assign({}, DEFAULT_SETTINGS);
    try {
      const s = await api('/api/vault/' + encodeURIComponent(state.vault) + '/settings');
      return Object.assign({}, DEFAULT_SETTINGS, s || {});
    } catch (_) { return Object.assign({}, DEFAULT_SETTINGS); }
  }
  function applySettings(s) {
    s = s || DEFAULT_SETTINGS;
    const r = document.documentElement.style;
    r.setProperty('--reader-font',    FONT_FAMILIES[s.font_family] || FONT_FAMILIES.system);
    r.setProperty('--reader-size',    s.font_size  + 'px');
    r.setProperty('--reader-leading', s.line_height);
    r.setProperty('--reader-margin',  s.margin + 'rem');
    r.setProperty('--reader-align',   s.alignment);
    r.setProperty('--reader-width',   s.max_width + 'px');
    r.setProperty('--reader-indent',  s.paragraph_indent + 'em');
    const themes = VALID_THEMES;
    for (const t of themes) document.body.classList.remove('theme-' + t);
    document.body.classList.add('theme-' + (themes.includes(s.theme) ? s.theme : 'default-dark'));
    state.infiniteScroll = !!s.infinite_scroll;
    // Sidebar position
    const pos = s.sidebar_position === 'right' ? 'right' : 'left';
    document.body.classList.remove('sidebar-left', 'sidebar-right');
    document.body.classList.add('sidebar-' + pos);
  }
  async function saveSettings(patch) {
    if (!state.vault) return;
    const updated = await api('/api/vault/' + encodeURIComponent(state.vault) + '/settings',
                              { method: 'PUT', body: patch });
    state.settings = Object.assign({}, DEFAULT_SETTINGS, updated);
    applySettings(state.settings);
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Settings modal                                                   //
  // ──────────────────────────────────────────────────────────────── //
  let settingsModal = null;
  function openSettings() {
    if (settingsModal) { closeSettings(); return; }
    const s = state.settings || DEFAULT_SETTINGS;
    const body = el('div', { class: 'modal-body' });

    // Theme picker
    body.appendChild(el('div', { style: 'font-weight:600;margin-bottom:0.3rem;' }, 'Theme'));
    const themeGrid = el('div', { class: 'theme-grid' });
    VALID_THEMES.forEach(t => {
      const label = t.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      const sw = el('div', {
        class: 'theme-swatch' + (s.theme === t ? ' active' : ''),
        'data-theme': t,
        onclick: () => {
          themeGrid.querySelectorAll('.theme-swatch').forEach(x => x.classList.remove('active'));
          sw.classList.add('active');
          saveSettings({ theme: t });
        },
      }, el('div', { class: 'preview' }), label);
      themeGrid.appendChild(sw);
    });
    body.appendChild(themeGrid);

    // Sliders + selects
    const rows = [
      ['Font family',
       select('font_family', [['system','System'],['serif','Serif'],['mono','Mono']], s.font_family)],
      ['Font size (px)',        slider('font_size', 12, 32, 1, s.font_size, v => v + 'px')],
      ['Line height',           slider('line_height', 1.2, 2.4, 0.05, s.line_height, v => v.toFixed(2))],
      ['Page margin (rem)',     slider('margin', 0.5, 4.0, 0.1, s.margin, v => v.toFixed(1))],
      ['Text alignment',
       select('alignment', [['left','Left'],['center','Center'],['right','Right'],['justify','Justify']], s.alignment)],
      ['Page width (px)',       slider('max_width', 500, 1400, 20, s.max_width, v => v + 'px')],
      ['Paragraph indent (em)', slider('paragraph_indent', 0, 4, 0.1, s.paragraph_indent, v => v.toFixed(1))],
      ['Fading edge',           slider('fading_edge', 0, 1, 1, s.fading_edge, v => v ? 'on' : 'off')],
      ['Infinite scroll',       slider('infinite_scroll', 0, 1, 1, s.infinite_scroll, v => v ? 'on' : 'off')],
      ['Sidebar position',
       select('sidebar_position', [['left','Left'],['right','Right']], s.sidebar_position || 'left')],
    ];
    rows.forEach(([label, input]) => body.appendChild(settingRow(label, input)));
    body.appendChild(el('p', { style: 'color:var(--muted);font-size:0.8rem;margin-top:0.5rem;' },
      'Settings save automatically. Theme & font also switch live.'));

    settingsModal = modal('Settings', body, null);
  }
  function closeSettings() {
    if (!settingsModal) return;
    settingsModal.remove(); settingsModal = null;
  }
  function settingRow(label, input) {
    const valEl = el('span', { class: 'value' }, input.dataset.display || '');
    input.addEventListener('input', () => { valEl.textContent = input.dataset.display = fmtDisplay(input); });
    input.addEventListener('change', () => {
      const v = input.type === 'range' ? parseFloat(input.value) : input.value;
      saveSettings({ [input.name]: v });
    });
    return el('div', { class: 'setting-row' }, el('label', null, label), valEl, input);
  }
  function select(name, opts, current) {
    const s = el('select', { name });
    for (const [v, l] of opts) {
      const o = el('option', { value: v }, l);
      if (v === current) o.selected = true;
      s.appendChild(o);
    }
    return s;
  }
  function slider(name, min, max, step, value, fmt) {
    // Coerce to number: sidecars may store floats as strings ("2.0") if
    // a previous tool wrote them that way. Browsers accept string values
    // for range inputs, but the fmt callback (e.g. `v => v.toFixed(2)`)
    // would throw on a string.
    const num = (typeof value === 'number') ? value : parseFloat(value);
    const v = Number.isFinite(num) ? num : 0;
    const i = el('input', { type: 'range', name, min, max, step, value: v });
    i.dataset.display = fmt(v);
    return i;
  }
  function fmtDisplay(input) {
    if (input.name === 'font_size' || input.name === 'max_width') return input.value + 'px';
    if (input.name === 'line_height' || input.name === 'margin' || input.name === 'paragraph_indent') {
      return parseFloat(input.value).toFixed(2).replace(/\.?0+$/, '');
    }
    if (input.name === 'fading_edge' || input.name === 'infinite_scroll') {
      return parseInt(input.value, 10) ? 'on' : 'off';
    }
    return input.value;
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Generic modal                                                    //
  // ──────────────────────────────────────────────────────────────── //
  function modal(title, body, footer) {
    const close = el('button', { onclick: () => overlay.remove() }, '\u00d7');
    const header = el('div', { class: 'modal-header' }, el('h2', null, title), close);
    const m = el('div', { class: 'modal' }, header, body,
                 footer ? el('div', { class: 'modal-footer' }, footer) : null);
    const overlay = el('div', {
      class: 'modal-overlay',
      onclick: (e) => { if (e.target === overlay) overlay.remove(); },
    }, m);
    document.body.appendChild(overlay);
    overlay.addEventListener('keydown', (e) => { if (e.key === 'Escape') overlay.remove(); });
    setTimeout(() => { const f = m.querySelector('input,select,textarea,button'); if (f) f.focus(); }, 0);
    return overlay;
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Highlight manager                                                //
  // ──────────────────────────────────────────────────────────────── //
  const HL = {
    load: async function(chapter) {
      if (!state.vault || !state.book) return [];
      try {
        const list = await api('/api/vault/' + encodeURIComponent(state.vault) +
                               '/book/' + encodeURIComponent(state.book) +
                               '/highlights?chapter=' + encodeURIComponent(chapter));
        return Array.isArray(list) ? list : [];
      } catch (_) { return []; }
    },
    add: async function(chapter, start, end, color, note) {
      return api('/api/vault/' + encodeURIComponent(state.vault) +
                 '/book/' + encodeURIComponent(state.book) + '/highlights',
                 { method: 'POST', body: { chapter, start, end, color, note: note || '' } });
    },
    remove: async function(id) {
      return api('/api/vault/' + encodeURIComponent(state.vault) +
                 '/book/' + encodeURIComponent(state.book) +
                 '/highlights/' + encodeURIComponent(id), { method: 'DELETE' });
    },
    update: async function(id, patch) {
      return api('/api/vault/' + encodeURIComponent(state.vault) +
                 '/book/' + encodeURIComponent(state.book) +
                 '/highlights/' + encodeURIComponent(id), { method: 'PUT', body: patch });
    },
    /**
     * Walk text nodes in rootEl, find the char-offset range [start, end),
     * and wrap the matching text in <mark>.
     */
    applyTo: function(rootEl, list) {
      if (!rootEl) return;
      // Wrap from end -> start so earlier offsets stay valid
      const sorted = list.slice().sort((a, b) => b.start - a.start);
      for (const h of sorted) this._wrapOne(rootEl, h.start, h.end, h);
    },
    _wrapOne: function(rootEl, start, end, h) {
      const walker = document.createTreeWalker(rootEl, NodeFilter.SHOW_TEXT, null);
      const targets = [];
      let pos = 0, node;
      while ((node = walker.nextNode())) {
        const len = node.nodeValue.length;
        if (pos + len <= start) { pos += len; continue; }
        if (pos >= end) break;
        const s = Math.max(0, start - pos);
        const e = Math.min(len, end - pos);
        targets.push({ node, s, e });
        pos += len;
      }
      for (let i = targets.length - 1; i >= 0; i--) {
        const { node, s, e } = targets[i];
        const middle = (s === 0) ? node : node.splitText(s);
        if (e < (s === 0 ? node.nodeValue.length : middle.nodeValue.length)) {
          middle.splitText(e - s);
        }
        const mark = document.createElement('mark');
        mark.dataset.id    = h.id;
        mark.dataset.color = h.color;
        if (h.note) { mark.title = h.note; mark.classList.add('has-note'); }
        middle.parentNode.insertBefore(mark, middle);
        mark.appendChild(middle);
      }
    },
    /**
     * Given a selection inside rootEl, compute the char-offset range.
     */
    offsetsFor: function(sel, rootEl) {
      if (!sel.rangeCount) return null;
      const range = sel.getRangeAt(0);
      if (!rootEl.contains(range.commonAncestorContainer)) return null;
      const pre = document.createRange();
      pre.selectNodeContents(rootEl);
      pre.setEnd(range.startContainer, range.startOffset);
      const start = pre.toString().length;
      const text  = range.toString();
      if (!text) return null;
      return { start, end: start + text.length, text };
    },
  };

  // ──────────────────────────────────────────────────────────────── //
  //  Selection popup (highlight colour picker)                       //
  // ──────────────────────────────────────────────────────────────── //
  let popupEl = null;
  function showSelectionPopup(x, y, range) {
    hideSelectionPopup();
    popupEl = el('div', { class: 'hl-popup', style: 'left:' + x + 'px;top:' + y + 'px;' });
    HL_COLORS.forEach(c => {
      popupEl.appendChild(el('button', {
        title: 'Highlight ' + c,
        onclick: (e) => { e.stopPropagation(); commitHighlight(c, range); },
      }, el('span', { class: 'hl-swatch', 'data-color': c })));
    });
    popupEl.appendChild(el('button', {
      title: 'Cancel',
      onclick: (e) => { e.stopPropagation(); hideSelectionPopup(); },
    }, '\u2715'));
    document.body.appendChild(popupEl);
  }
  function hideSelectionPopup() { if (popupEl) { popupEl.remove(); popupEl = null; } }
  async function commitHighlight(color, range) {
    if (!state.currentChapter) { hideSelectionPopup(); return; }
    const off = HL.offsetsFor(range, document.getElementById('reader-body'));
    hideSelectionPopup();
    if (!off) return;
    try {
      const h = await HL.add(state.currentChapter, off.start, off.end, color, '');
      state.highlights.push(Object.assign({ chapter: state.currentChapter }, h));
      HL.applyTo(document.getElementById('reader-body'), [h]);
    } catch (err) { alert('Highlight failed: ' + err.message); }
  }
  function bindSelectionPopup() {
    const reader = () => document.getElementById('reader-body');
    document.addEventListener('mouseup', () => {
      const sel = window.getSelection();
      if (!sel || !sel.toString()) { hideSelectionPopup(); return; }
      const r = reader(); if (!r) return;
      const off = HL.offsetsFor(sel, r);
      if (!off) { hideSelectionPopup(); return; }
      const rect = sel.getRangeAt(0).getBoundingClientRect();
      showSelectionPopup(rect.left + window.scrollX, rect.top + window.scrollY - 40, sel);
    });
    document.addEventListener('mousedown', (e) => {
      if (popupEl && !popupEl.contains(e.target)) hideSelectionPopup();
    });
  }
  function bindMarkClicks() {
    document.addEventListener('click', (e) => {
      const m = e.target.closest('mark[data-id]');
      if (!m) return;
      const id = m.dataset.id;
      const h = state.highlights.find(x => x.id === id);
      if (!h) return;
      openHighlightEditor(h, m);
    });
  }
  function openHighlightEditor(h, markEl) {
    const ta = el('textarea', { placeholder: 'Note (optional)' });
    ta.value = h.note || '';
    const colorRow = el('div', { style: 'display:flex;gap:0.4rem;margin-bottom:0.5rem;' });
    HL_COLORS.forEach(c => {
      const sw = el('span', {
        class: 'hl-swatch', 'data-color': c,
        style: 'cursor:pointer;border:2px solid ' + (c === h.color ? 'var(--primary)' : 'transparent') + ';',
        onclick: () => {
          h.color = c; markEl.dataset.color = c;
          colorRow.querySelectorAll('.hl-swatch').forEach(x => x.style.border = '2px solid transparent');
          sw.style.border = '2px solid var(--primary)';
        },
      });
      colorRow.appendChild(sw);
    });
    const save = el('button', {
      onclick: async () => {
        const updated = await HL.update(h.id, { color: h.color, note: ta.value });
        h.note = updated.note; h.color = updated.color;
        if (h.note) { markEl.title = h.note; markEl.classList.add('has-note'); }
        else { markEl.removeAttribute('title'); markEl.classList.remove('has-note'); }
        overlay.remove();
      },
    }, 'Save');
    const del = el('button', {
      style: 'background:#c44;color:white;border:0;padding:0.4rem 0.8rem;border-radius:6px;cursor:pointer;margin-right:auto;',
      onclick: async () => {
        await HL.remove(h.id);
        markEl.replaceWith(...Array.from(markEl.childNodes));
        state.highlights = state.highlights.filter(x => x.id !== h.id);
        overlay.remove();
      },
    }, 'Delete');
    const body = el('div', { class: 'note-editor' }, colorRow, ta,
                    el('div', { style: 'display:flex;gap:0.5rem;margin-top:0.6rem;justify-content:space-between;' },
                       del, save));
    const overlay = modal('Edit highlight', body, null);
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Bookmark manager                                                 //
  // ──────────────────────────────────────────────────────────────── //
  const BM = {
    load: async function(chapter) {
      if (!state.vault || !state.book) return [];
      try {
        const list = await api('/api/vault/' + encodeURIComponent(state.vault) +
                               '/book/' + encodeURIComponent(state.book) +
                               '/bookmarks?chapter=' + encodeURIComponent(chapter));
        return Array.isArray(list) ? list : [];
      } catch (_) { return []; }
    },
    add: async function(chapter, label, anchor) {
      return api('/api/vault/' + encodeURIComponent(state.vault) +
                 '/book/' + encodeURIComponent(state.book) + '/bookmarks',
                 { method: 'POST', body: { chapter, label: label || '(bookmark)', anchor } });
    },
    remove: async function(id) {
      return api('/api/vault/' + encodeURIComponent(state.vault) +
                 '/book/' + encodeURIComponent(state.book) +
                 '/bookmarks/' + encodeURIComponent(id), { method: 'DELETE' });
    },
  };
  async function quickBookmark() {
    if (!state.currentChapter) return;
    const anchor = document.getElementById('content').scrollTop;
    const label  = (state.catalog.chapters[state.chapterIndex].title) || ('Chapter ' + (state.chapterIndex + 1));
    try {
      const b = await BM.add(state.currentChapter, label, anchor);
      state.bookmarks.push(b);
      toast('Bookmark saved: ' + label);
    } catch (err) { alert('Bookmark failed: ' + err.message); }
  }
  function toast(msg) {
    const t = el('div', { style: 'position:fixed;bottom:1.5rem;left:50%;transform:translateX(-50%);' +
                                'background:var(--card);color:var(--text);border:1px solid var(--border);' +
                                'border-radius:6px;padding:0.5rem 1rem;z-index:300;box-shadow:0 4px 12px rgba(0,0,0,0.3);' },
      msg);
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2200);
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Position (debounced 1s save)                                    //
  // ──────────────────────────────────────────────────────────────── //
  async function loadPosition(bookId) {
    if (!state.vault) return null;
    try {
      return await api('/api/vault/' + encodeURIComponent(state.vault) +
                       '/book/' + encodeURIComponent(bookId) + '/position');
    } catch (_) { return null; }
  }
  function savePositionDebounced() {
    clearTimeout(state.savePosTimer);
    state.savePosTimer = setTimeout(savePositionNow, 1000);
  }
  async function savePositionNow() {
    if (!state.vault || !state.book || state.chapterIndex == null) return;
    let chapter = state.chapterIndex, scroll = 0;
    if (state.infiniteScroll) {
      const info = activeChapterInfo();
      chapter = info.idx; scroll = info.local;
    } else {
      scroll = document.getElementById('content').scrollTop;
    }
    try {
      await api('/api/vault/' + encodeURIComponent(state.vault) +
                '/book/' + encodeURIComponent(state.book) + '/position',
                { method: 'PUT', body: { chapter: chapter, scroll: scroll } });
    } catch (_) {}
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Progress bar                                                     //
  // ──────────────────────────────────────────────────────────────── //
  function updateProgressBar() {
    const bar = document.getElementById('read-progress');
    if (!bar || !state.catalog || !state.catalog.chapters) return;
    if (!state.catalog.chapters.length) { bar.style.width = '0%'; return; }
    let pct = 0;
    if (state.infiniteScroll) {
      const info = activeChapterInfo();
      const ct = document.getElementById('content');
      if (!ct) return;
      const block = ct.querySelector('[data-chapter-idx="' + info.idx + '"]');
      const blockHeight = block ? block.offsetHeight : 1;
      const localFrac = Math.min(1, Math.max(0, info.local / Math.max(1, blockHeight)));
      pct = ((info.idx + localFrac) / state.catalog.chapters.length) * 100;
    } else {
      const ct = document.getElementById('content');
      if (!ct) return;
      const maxScroll = Math.max(1, ct.scrollHeight - ct.clientHeight);
      const localFrac = Math.min(1, Math.max(0, ct.scrollTop / maxScroll));
      pct = ((state.chapterIndex + localFrac) / state.catalog.chapters.length) * 100;
    }
    bar.style.width = Math.min(100, pct) + '%';
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Reading time estimate                                            //
  // ──────────────────────────────────────────────────────────────── //
  function updateReadingTime() {
    const el = document.getElementById('reading-time');
    if (!el || !state.catalog) return;
    const totalWords = state.catalog.total_words || 0;
    if (!totalWords) { el.textContent = ''; return; }
    const chCount = state.catalog.chapters.length || 1;
    const wordsPerChapter = totalWords / chCount;
    let completedChapters = state.chapterIndex;
    let chapterFrac = 0;
    if (state.infiniteScroll) {
      const info = activeChapterInfo();
      completedChapters = info.idx;
      const ct = document.getElementById('content');
      const block = ct ? ct.querySelector('[data-chapter-idx="' + info.idx + '"]') : null;
      const blockHeight = block ? block.offsetHeight : 1;
      chapterFrac = Math.min(1, Math.max(0, info.local / Math.max(1, blockHeight)));
    } else {
      const ct = document.getElementById('content');
      if (ct) {
        const maxScroll = Math.max(1, ct.scrollHeight - ct.clientHeight);
        chapterFrac = Math.min(1, Math.max(0, ct.scrollTop / maxScroll));
      }
    }
    const wordsRead = (completedChapters + chapterFrac) * wordsPerChapter;
    const wordsRemaining = Math.max(0, totalWords - wordsRead);
    const minsRemaining = Math.ceil(wordsRemaining / 200);
    let text = '';
    if (minsRemaining <= 0) text = 'Finishing...';
    else if (minsRemaining < 60) text = '~' + minsRemaining + ' min left';
    else if (minsRemaining % 60 === 0) text = '~' + Math.floor(minsRemaining / 60) + ' hr left';
    else text = '~' + Math.floor(minsRemaining / 60) + ' hr ' + (minsRemaining % 60) + ' min left';
    el.textContent = text;
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Topbar auto-hide                                                 //
  // ──────────────────────────────────────────────────────────────── //
  let idleTimer = null;
  function resetIdleTimer() {
    document.querySelector('.topbar').classList.remove('hidden');
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      if (!document.querySelector('.modal-overlay, .zoom-modal, .hl-popup')) {
        document.querySelector('.topbar').classList.add('hidden');
      }
    }, 3500);
  }
  function bindIdleTimer() {
    ['mousemove','keydown','scroll'].forEach(ev => {
      document.addEventListener(ev, resetIdleTimer, {passive:true});
    });
  }

  // ──────────────────────────────────────────────────────────────── //
  //  End-of-book card                                                 //
  // ──────────────────────────────────────────────────────────────── //
  function appendEndCard() {
    if (!state.catalog || !state.catalog.chapters) return;
    if (state.appendedIdx < state.catalog.chapters.length - 1) return;
    const body = document.getElementById('reader-body');
    if (!body) return;
    if (body.querySelector('.end-book-card')) return;
    const card = el('div', { class: 'end-book-card' },
      el('h2', null, 'End of book'),
      el('p', null, 'You have finished reading.'),
      el('button', { onclick: () => { savePositionNow(); renderBookList(state.books); } }, 'Back to library')
    );
    body.appendChild(card);
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Click-to-turn pages                                              //
  // ──────────────────────────────────────────────────────────────── //
  function bindClickToTurn() {
    document.addEventListener('click', (e) => {
      if (!isReader()) return;
      const sidebarEl = document.getElementById('sidebar');
      const sidebarOpen = sidebarEl && sidebarEl.matches(':hover');
      if (e.target.closest('a, button, mark, input, textarea, img, .modal-overlay, .zoom-modal, .hl-popup')) return;
      const vw = window.innerWidth;
      const x = e.clientX;
      const ct = document.getElementById('content');
      if (!ct) return;
      const pageH = Math.max(300, Math.round((ct.clientHeight || 600) * 0.85));
      const pos = (state.settings && state.settings.sidebar_position === 'right') ? 'right' : 'left';
      if (x < vw * 0.15 && pos !== 'left') { ct.scrollBy({ top: -pageH, behavior: 'smooth' }); return; }
      if (x > vw * 0.85 && pos !== 'right') { ct.scrollBy({ top: pageH, behavior: 'smooth' }); return; }
    });
  }

  // ──────────────────────────────────────────────────────────────── //
  //  In-chapter search                                               //
  // ──────────────────────────────────────────────────────────────── //
  let searchMatches = [], searchIdx = -1, searchPanel = null;
  function openInChapterSearch() {
    if (searchPanel) { closeInChapterSearch(); return; }
    const input = el('input', { type: 'search', placeholder: 'Find in current chapter…', autocomplete: 'off' });
    const count = el('span', { class: 'count' }, '');
    const prev  = el('button', { onclick: () => findInChapter(input.value, -1) }, '\u2191');
    const next  = el('button', { onclick: () => findInChapter(input.value, +1) }, '\u2193');
    const close = el('button', { onclick: closeInChapterSearch }, '\u2715');
    searchPanel = el('div', { class: 'ic-search' }, input, count, prev, next, close);
    const c = document.getElementById('content');
    c.insertBefore(searchPanel, c.firstChild.nextSibling);
    input.addEventListener('input', () => findInChapter(input.value, 0));
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); findInChapter(input.value, e.shiftKey ? -1 : +1); }
      if (e.key === 'Escape') closeInChapterSearch();
    });
    input.focus();
  }
  function closeInChapterSearch() {
    if (!searchPanel) return;
    clearInChapterMatches();
    searchPanel.remove(); searchPanel = null;
  }
  function clearInChapterMatches() {
    const body = document.getElementById('reader-body');
    if (!body) return;
    body.querySelectorAll('.ic-match').forEach(m => {
      const parent = m.parentNode;
      while (m.firstChild) parent.insertBefore(m.firstChild, m);
      parent.removeChild(m); parent.normalize();
    });
    searchMatches = []; searchIdx = -1;
  }
  function findInChapter(q, dir) {
    const body = document.getElementById('reader-body');
    if (!body) return;
    clearInChapterMatches();
    if (!q) {
      if (searchPanel) searchPanel.querySelector('.count').textContent = '';
      return;
    }
    // Scope: under infinite scroll, search only the active chapter block.
    let scope = body;
    if (state.infiniteScroll) {
      const info = activeChapterInfo();
      const block = body.querySelector('[data-chapter-idx="' + info.idx + '"]');
      if (!block) { searchPanel.querySelector('.count').textContent = '0/0'; return; }
      scope = block;
    }
    const walker = document.createTreeWalker(scope, NodeFilter.SHOW_TEXT, null);
    const nodes = []; let n;
    while ((n = walker.nextNode())) nodes.push(n);
    searchMatches = [];
    const re = new RegExp(escapeRegex(q), 'gi');
    for (const node of nodes) {
      const text = node.nodeValue;
      re.lastIndex = 0;
      let m;
      const parts = [];
      let last = 0;
      while ((m = re.exec(text)) != null) {
        if (m.index > last) parts.push(document.createTextNode(text.slice(last, m.index)));
        const span = document.createElement('span');
        span.className = 'ic-match';
        span.textContent = m[0];
        parts.push(span);
        searchMatches.push(span);
        last = m.index + m[0].length;
        if (m[0].length === 0) re.lastIndex++;
      }
      if (parts.length === 0) continue;
      if (last < text.length) parts.push(document.createTextNode(text.slice(last)));
      const parent = node.parentNode;
      parts.forEach(p => parent.insertBefore(p, node));
      parent.removeChild(node);
    }
    if (searchMatches.length === 0) {
      searchPanel.querySelector('.count').textContent = '0/0';
      return;
    }
    searchIdx = dir > 0 ? 0 : (searchMatches.length - 1);
    scrollToCurrentMatch();
  }
  function scrollToCurrentMatch() {
    searchMatches.forEach(m => m.classList.remove('cur'));
    if (searchIdx < 0) searchIdx = searchMatches.length - 1;
    if (searchIdx >= searchMatches.length) searchIdx = 0;
    const m = searchMatches[searchIdx];
    m.classList.add('cur');
    m.scrollIntoView({ behavior: 'smooth', block: 'center' });
    searchPanel.querySelector('.count').textContent = (searchIdx + 1) + '/' + searchMatches.length;
  }
  function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  // ──────────────────────────────────────────────────────────────── //
  //  Image zoom                                                       //
  // ──────────────────────────────────────────────────────────────── //
  function bindImageZoom() {
    document.addEventListener('click', (e) => {
      const img = e.target.closest('#content.reader img');
      if (!img) return;
      if (img.closest('.zoom-modal')) return;
      const src = img.getAttribute('src');
      if (!src) return;
      const zoom = el('div', { class: 'zoom-modal', onclick: () => zoom.remove() },
                      el('img', { src }));
      document.body.appendChild(zoom);
    });
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Keyboard                                                         //
  // ──────────────────────────────────────────────────────────────── //
  function bindKeyboard() {
    document.addEventListener('keydown', (e) => {
      // Don't hijack typing in inputs
      const inField = e.target.matches('input, textarea, select');
      if (e.key === 'Escape') {
        if (inField) { e.target.blur(); return; }
        if (document.querySelector('.modal-overlay, .zoom-modal') ||
            settingsModal || searchPanel || popupEl) {
          closeSettings(); closeInChapterSearch();
          document.querySelectorAll('.modal-overlay, .zoom-modal').forEach(m => m.remove());
          hideSelectionPopup();
          return;
        }
        // Toggle zen mode
        document.body.classList.toggle('zen');
        return;
      }
      if (inField) return;

      // Quick themes 1-8
      if (e.key >= '1' && e.key <= '8' && !e.metaKey && !e.ctrlKey) {
        saveSettings({ theme: VALID_THEMES[parseInt(e.key, 10) - 1] });
        if (settingsModal) openSettings();
        return;
      }
      if (e.key === '?') { showShortcuts(); return; }
      if (e.key === ',') { openSettings(); return; }
      if (e.key === '/') { e.preventDefault(); openInChapterSearch(); return; }
      if (e.key.toLowerCase() === 'b') { e.preventDefault(); quickBookmark(); return; }
      // Shift+Arrow = chapter nav (overrides plain-arrow scroll below)
      if (e.shiftKey && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) {
        e.preventDefault();
        if (e.key === 'ArrowRight') nextChapter(); else prevChapter();
        return;
      }
      const c = document.getElementById('content');
      const lineH = Math.round(((state.settings && state.settings.font_size) || 18) * 1.4);
      const pageH = Math.max(300, Math.round((c.clientHeight || 600) * 0.85));
      if (e.key === 'ArrowUp')    { e.preventDefault(); c.scrollBy({ top: -lineH }); return; }
      if (e.key === 'ArrowDown')  { e.preventDefault(); c.scrollBy({ top:  lineH }); return; }
      if (e.key === 'ArrowLeft')  { e.preventDefault(); c.scrollBy({ top: -pageH }); return; }
      if (e.key === 'ArrowRight') { e.preventDefault(); c.scrollBy({ top:  pageH }); return; }
      if (e.key === 'PageUp' || e.key === 'PageDown' || e.key === ' ') {
        e.preventDefault();
        c.scrollBy({ top: e.key === 'PageUp' ? -pageH : pageH });
        return;
      }
      if (e.key === 'Home') { c.scrollTo({ top: 0 }); return; }
      if (e.key === 'End')  { c.scrollTo({ top: c.scrollHeight }); return; }
    });
  }
  function isReader() { return state.catalog && state.currentChapter; }

  function showShortcuts() {
    const dl = el('dl', { class: 'shortcuts' });
    const rows = [
      ['\u2191 / \u2193',           'scroll one line'],
      ['\u2190 / \u2192',           'scroll one page'],
      ['Shift+\u2190 / \u2192',     'prev / next chapter'],
      ['Space / PgUp / PgDn',       'page scroll'],
      ['Home / End',                'chapter start / end'],
      ['/',                         'find in current chapter'],
      ['b',                         'bookmark current scroll position'],
      ['1 \u2013 8',                'quick-switch theme'],
      [',',                         'open settings'],
      ['?',                         'this overlay'],
      ['Esc',                       'close any panel'],
    ];
    for (const [k, d] of rows) {
      dl.appendChild(el('dt', null, k));
      dl.appendChild(el('dd', null, d));
    }
    modal('Keyboard shortcuts', dl, null);
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Mobile gestures (swipe \u2190/\u2192, swipe down from top)                       //
  // ──────────────────────────────────────────────────────────────── //
  function bindGestures() {
    const start = { x: 0, y: 0, t: 0 };
    const c = document.getElementById('content');
    c.addEventListener('touchstart', (e) => {
      if (e.touches.length !== 1) return;
      start.x = e.touches[0].clientX;
      start.y = e.touches[0].clientY;
      start.t = Date.now();
    }, { passive: true });
    c.addEventListener('touchend', (e) => {
      if (e.changedTouches.length !== 1) return;
      const dx = e.changedTouches[0].clientX - start.x;
      const dy = e.changedTouches[0].clientY - start.y;
      const dt = Date.now() - start.t;
      if (dt > 600) return;
      if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.5) {
        if (dx < 0) nextChapter(); else prevChapter();
        return;
      }
      if (dy > 80 && start.y < 80) { openSettings(); return; }
    });
  }
  function nextChapter() {
    if (!state.catalog || !state.catalog.chapters) return;
    const target = (state.chapterIndex || 0) + 1;
    if (target >= state.catalog.chapters.length) return;
    if (state.infiniteScroll) scrollToChapter(target, 0);
    else loadChapter(target);
  }
  function prevChapter() {
    if (!state.catalog || !state.catalog.chapters) return;
    const cur = state.chapterIndex || 0;
    if (cur <= 0) return;
    if (state.infiniteScroll) {
      // If we have chapter cur-1 appended, scroll to its top.
      // If not, do a fresh load of it (no appended preceding chapters).
      const ct = document.getElementById('content');
      const block = ct.querySelector('[data-chapter-idx="' + (cur - 1) + '"]');
      if (block) ct.scrollTop = block.offsetTop;
      else loadChapter(cur - 1);
    } else if (cur > 0) loadChapter(cur - 1);
  }
  async function scrollToChapter(idx, localOffset) {
    if (!state.catalog || !state.catalog.chapters[idx]) return;
    if (state.infiniteScroll && idx <= state.appendedIdx) {
      const ct = document.getElementById('content');
      const block = ct.querySelector('[data-chapter-idx="' + idx + '"]');
      if (block) ct.scrollTop = block.offsetTop + (localOffset || 0);
    } else {
      // Not appended yet (or single mode) — open that chapter fresh
      loadChapter(idx, localOffset || 0);
    }
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Views: vaults, book list, reader sidebar, chapter loader        //
  // ──────────────────────────────────────────────────────────────── //
  function buildShell() {
    const root = document.getElementById('app');
    const sb   = el('aside', { id: 'sidebar' });
    const ct   = el('section', { id: 'content' });
    root.appendChild(sb); root.appendChild(ct);
    const toggle = document.getElementById('sidebar-toggle');
    toggle.addEventListener('click', () => {
      sb.classList.toggle('open');
      if (sb.classList.contains('open')) {
        sb.style.transform = 'translateX(0)';
      } else {
        sb.style.transform = '';
      }
    });
    document.getElementById('open-settings').addEventListener('click', openSettings);
    document.getElementById('search').addEventListener('input', (e) => {
      const q = e.target.value.trim();
      if (!state.vault) return;
      if (!q) { renderBookList(state.books); return; }
      const scope = state.book ? 'all' : 'all';
      const bidParam = state.book ? '&book_id=' + encodeURIComponent(state.book) : '';
      api('/api/vault/' + encodeURIComponent(state.vault) + '/search?q=' + encodeURIComponent(q) +
          '&scope=' + scope + bidParam)
        .then(data => renderSearchResults(data, q)).catch(err => { ct.innerHTML = '<p class="placeholder">' + err.message + '</p>'; });
    });
  }

  function renderVaults() {
    const ct = document.getElementById('content');
    const sb = document.getElementById('sidebar');
    sb.innerHTML = ''; sb.classList.remove('open');
    document.getElementById('app-title').textContent = 'smoltome';
    ct.className = '';
    ct.innerHTML = '<h2 style="margin-top:0;">Select a vault</h2>' +
      '<div class="vault-list">' + state.vaults.map(v => (
        '<div class="card"><h3>' + escapeHtml(v.name) + '</h3>' +
        '<p>' + escapeHtml(v.path) + '</p>' +
        '<div class="actions"><button data-name="' + escapeHtml(v.name) + '">Open</button></div></div>'
      )).join('') + '</div>';
    ct.querySelectorAll('button[data-name]').forEach(b => {
      b.addEventListener('click', () => selectVault(b.dataset.name));
    });
  }

  async function selectVault(name) {
    state.vault = name;
    state.settings = await loadSettings();
    applySettings(state.settings);
    document.getElementById('sidebar').classList.remove('open');
    try {
      state.books = await api('/api/vault/' + encodeURIComponent(name) + '/books');
      renderBookList(state.books);
    } catch (err) {
      document.getElementById('content').innerHTML = '<p class="placeholder">' + err.message + '</p>';
    }
  }

  function renderBookList(books) {
    const sb = document.getElementById('sidebar');
    const ct = document.getElementById('content');
    sb.classList.remove('open');
    document.getElementById('app-title').textContent = 'smoltome';
    sb.innerHTML = '<h3>Vault</h3><a class="active">' + escapeHtml(state.vault) + '</a>' +
                   '<h3>Books</h3>' + books.map(b =>
      '<a data-id="' + escapeHtml(b.book_id) + '">' + escapeHtml(b.title) + '</a>'
    ).join('');
    sb.querySelectorAll('a[data-id]').forEach(a => {
      a.addEventListener('click', () => { sb.classList.remove('open'); sb.style.transform = ''; openBook(a.dataset.id); });
    });
    ct.className = '';
    if (books.length === 0) {
      ct.innerHTML = '<p class="placeholder">No books found.</p>'; return;
    }
    ct.innerHTML = '<div class="book-grid">' + books.map(b => {
      const pct = b.progress != null ? Math.round(b.progress) : 0;
      const circumference = 2 * Math.PI * 14;
      const offset = circumference * (1 - pct / 100);
      const ring = pct > 0 ? '<svg class="progress-ring" viewBox="0 0 36 36">' +
        '<circle cx="18" cy="18" r="14" stroke="rgba(0,0,0,0.2)" stroke-width="3" fill="none"/>' +
        '<circle class="ring-fill" cx="18" cy="18" r="14" stroke-width="3" fill="none" ' +
        'stroke-dasharray="' + circumference + '" stroke-dashoffset="' + offset + '"/>' +
        '</svg>' : '';
      const cover = b.cover
        ? '<img class="cover" loading="lazy" src="/api/vault/' + encodeURIComponent(state.vault) +
          '/image/' + encodeURIComponent(b.book_id) + '/' + encodeURIComponent(b.cover) + '" alt="">'
        : '<div class="cover-placeholder">' + (b.title || '?').charAt(0).toUpperCase() + '</div>';
      return '<div class="book-item" data-id="' + escapeHtml(b.book_id) + '">' +
        '<div class="cover-wrap">' + cover + ring + '</div>' +
        '<h3>' + escapeHtml(b.title) + '</h3>' +
        '<p>by ' + escapeHtml(b.author || 'Unknown') + '</p></div>';
    }).join('') + '</div>';
    ct.querySelectorAll('.book-item').forEach(item => {
      item.addEventListener('click', () => { openBook(item.dataset.id); });
    });
  }

  function renderSearchResults(data, query) {
    const ct = document.getElementById('content');
    const sb = document.getElementById('sidebar');
    sb.classList.remove('open');
    document.getElementById('app-title').textContent = 'smoltome';
    sb.innerHTML = '<h3>Vault</h3><a class="active">' + escapeHtml(state.vault) + '</a>' +
                   '<h3>Books</h3>' + (data.books || []).map(b =>
      '<a data-id="' + escapeHtml(b.book_id) + '">' + escapeHtml(b.title) + '</a>'
    ).join('');
    sb.querySelectorAll('a[data-id]').forEach(a => {
      a.addEventListener('click', () => { sb.classList.remove('open'); sb.style.transform = ''; openBook(a.dataset.id); });
    });
    ct.className = '';

    if ((!(data.books || []).length) && (!(data.content_matches || []).length)) {
      ct.innerHTML = '<p class="placeholder">No results for "' + escapeHtml(query) + '".</p>';
      return;
    }

    let html = '';

    if ((data.content_matches || []).length) {
      html += '<h2 style="margin-top:0;">Matches in text</h2>';
      html += '<div class="content-matches">';
      data.content_matches.forEach(m => {
        const cardId = 'cm-' + escapeHtml(m.book_id) + '-' + escapeHtml(m.chapter_file);
        html +=
          '<div class="match-card" data-book="' + escapeHtml(m.book_id) +
          '" data-chapter="' + escapeHtml(m.chapter_file) +
          '" id="' + cardId + '">' +
          '<div class="match-header">' +
          '<span class="match-book-title">' + escapeHtml(m.title) + '</span>' +
          (m.author ? '<span class="match-author">by ' + escapeHtml(m.author) + '</span>' : '') +
          '</div>' +
          '<div class="match-chapter">' + escapeHtml(m.chapter_title || m.chapter_file) + '</div>' +
          '<div class="match-snippet">' + (m.snippet || '') + '</div>' +
          '</div>';
      });
      html += '</div>';
    }

    if ((data.books || []).length) {
      html += '<h2 style="margin-top:' + ((data.content_matches || []).length ? '1.5rem' : '0') + ';">Books</h2>';
      html += '<div class="book-grid">' + data.books.map(b => {
        const pct = b.progress != null ? Math.round(b.progress) : 0;
        const circumference = 2 * Math.PI * 14;
        const offset = circumference * (1 - pct / 100);
        const ring = pct > 0 ? '<svg class="progress-ring" viewBox="0 0 36 36">' +
          '<circle cx="18" cy="18" r="14" stroke="rgba(0,0,0,0.2)" stroke-width="3" fill="none"/>' +
          '<circle class="ring-fill" cx="18" cy="18" r="14" stroke-width="3" fill="none" ' +
          'stroke-dasharray="' + circumference + '" stroke-dashoffset="' + offset + '"/>' +
          '</svg>' : '';
        const cover = b.cover
          ? '<img class="cover" loading="lazy" src="/api/vault/' + encodeURIComponent(state.vault) +
            '/image/' + encodeURIComponent(b.book_id) + '/' + encodeURIComponent(b.cover) + '" alt="">'
          : '<div class="cover-placeholder">' + (b.title || '?').charAt(0).toUpperCase() + '</div>';
        return '<div class="book-item" data-id="' + escapeHtml(b.book_id) + '">' +
          '<div class="cover-wrap">' + cover + ring + '</div>' +
          '<h3>' + escapeHtml(b.title) + '</h3>' +
          '<p>by ' + escapeHtml(b.author || 'Unknown') + '</p></div>';
      }).join('') + '</div>';
    }

    ct.innerHTML = html;

    ct.querySelectorAll('.book-item').forEach(item => {
      item.addEventListener('click', () => { openBook(item.dataset.id); });
    });

    ct.querySelectorAll('.match-card').forEach(card => {
      card.addEventListener('click', async () => {
        const bid = card.dataset.book;
        const chFile = card.dataset.chapter;
        if (!bid || !chFile) return;
        await openBook(bid);
        const idx = (state.catalog.chapters || []).findIndex(c => c.file === chFile);
        if (idx >= 0) {
          if (state.infiniteScroll) scrollToChapter(idx, 0);
          else loadChapter(idx);
        }
      });
    });
  }

  async function openBook(bookId) {
    state.book = bookId;
    const sb = document.getElementById('sidebar');
    sb.classList.remove('open');
    sb.style.transform = '';
    try {
      state.catalog = await api('/api/vault/' + encodeURIComponent(state.vault) +
                                '/book/' + encodeURIComponent(bookId) + '/catalog');
      document.getElementById('app-title').textContent = state.catalog.title || 'smoltome';
      const pos = await loadPosition(bookId);
      renderReaderSidebar();
      if (state.catalog.chapters && state.catalog.chapters.length) {
        const idx = (pos && Number.isInteger(pos.chapter) && pos.chapter < state.catalog.chapters.length)
                    ? pos.chapter : 0;
        loadChapter(idx, pos ? pos.scroll : 0);
      } else {
        const ct = document.getElementById('content');
        ct.className = 'reader';
        ct.innerHTML = '<p class="placeholder">This book has no chapters.</p>';
      }
    } catch (err) {
      document.getElementById('content').innerHTML = '<p class="placeholder">' + err.message + '</p>';
    }
  }

  function renderReaderSidebar() {
    const sb = document.getElementById('sidebar');
    const c  = state.catalog;
    const pos = (state.settings && state.settings.sidebar_position === 'right') ? 'right' : 'left';
    sb.innerHTML =
      '<h3>Book</h3>' +
      '<a id="back-to-books">&larr; All books</a>' +
      '<h3>' + escapeHtml(c.title) + '</h3>' +
      '<p style="padding:0 0.7rem;color:var(--muted);font-size:0.85rem;">' + escapeHtml(c.author || '') + '</p>' +
      '<h3>Chapters</h3>' +
      (c.chapters || []).map((ch, i) =>
        '<a data-idx="' + i + '">' + escapeHtml(ch.title || ch.file) + '</a>'
      ).join('') +
      '<h3 class="bm-heading" style="display:none;">Bookmarks</h3>' +
      '<div class="bm-list"></div>' +
      '<button class="sidebar-pos-toggle" title="Toggle sidebar position">\u21c4 ' + (pos === 'left' ? 'Right' : 'Left') + '</button>';
    sb.querySelector('#back-to-books').addEventListener('click', () => {
      savePositionNow(); renderBookList(state.books);
    });
    sb.querySelectorAll('a[data-idx]').forEach(a => {
      a.addEventListener('click', () => {
        sb.classList.remove('open');
        sb.style.transform = '';
        loadChapter(parseInt(a.dataset.idx, 10));
      });
    });
    // Position toggle button
    sb.querySelector('.sidebar-pos-toggle').addEventListener('click', () => {
      const newPos = pos === 'left' ? 'right' : 'left';
      document.body.classList.remove('sidebar-left', 'sidebar-right');
      document.body.classList.add('sidebar-' + newPos);
      state.settings.sidebar_position = newPos;
      saveSettings({ sidebar_position: newPos });
      setTimeout(() => renderReaderSidebar(), 100);
    });
    highlightActiveChapter();
    markReadChapters();
  }

  function highlightActiveChapter() {
    document.querySelectorAll('#sidebar a[data-idx]').forEach(a => {
      a.classList.toggle('active', parseInt(a.dataset.idx, 10) === state.chapterIndex);
    });
  }

  function markReadChapters() {
    if (!state.catalog || !state.catalog.chapters) return;
    document.querySelectorAll('#sidebar a[data-idx]').forEach(a => {
      const idx = parseInt(a.dataset.idx, 10);
      if (idx < state.chapterIndex) a.classList.add('read');
      else a.classList.remove('read');
    });
  }

  async function loadChapter(idx, restoreScroll) {
    if (!state.catalog || !state.catalog.chapters || !state.catalog.chapters[idx]) return;
    // Reset infinite-scroll state for the new chapter context
    state.appendedIdx = -1;
    state.appendQueue = Promise.resolve();
    if (state.scrollListener) {
      const ct = document.getElementById('content');
      if (ct) ct.removeEventListener('scroll', state.scrollListener);
      state.scrollListener = null;
    }
    if (state.infiniteScroll) return loadChapterInfinite(idx, restoreScroll);
    return loadChapterSingle(idx, restoreScroll);
  }
  async function loadChapterSingle(idx, restoreScroll) {
    state.chapterIndex = idx;
    highlightActiveChapter();
    const ch = state.catalog.chapters[idx];
    state.currentChapter = ch.file;
    const ct = document.getElementById('content');
    try {
      const md = await api('/api/vault/' + encodeURIComponent(state.vault) +
                           '/book/' + encodeURIComponent(state.book) +
                           '/chapter/' + encodeURIComponent(ch.file));
      let html = mdToHtml(md);
      html = rewriteImgSrcs(html);
      ct.className = 'reader' + (state.settings && state.settings.fading_edge ? ' fading-edge' : '');
      ct.innerHTML = '';
      ct.appendChild(buildReaderToolbar(ch));
      const body = el('div', { id: 'reader-body' });
      body.innerHTML = html;
      ct.appendChild(body);
      const [hl, bm] = await Promise.all([HL.load(ch.file), BM.load(ch.file)]);
      state.highlights = hl; state.bookmarks = bm;
      HL.applyTo(body, hl);
      renderBookmarksInSidebar();
      if (typeof restoreScroll === 'number') ct.scrollTop = restoreScroll;
      else ct.scrollTop = 0;
      updateProgressBar();
      updateReadingTime();
      if (state.scrollListener) ct.removeEventListener('scroll', state.scrollListener);
      state.scrollListener = () => { savePositionDebounced(); updateProgressBar(); updateReadingTime(); resetIdleTimer(); };
      ct.addEventListener('scroll', state.scrollListener);
      window.addEventListener('beforeunload', savePositionNow);
      if (idx === state.catalog.chapters.length - 1) {
        const endCard = el('div', { class: 'end-book-card' },
          el('h2', null, 'End of book'),
          el('p', null, 'You have finished reading.'),
          el('button', { onclick: () => { savePositionNow(); renderBookList(state.books); } }, 'Back to library')
        );
        ct.appendChild(endCard);
      }
    } catch (err) { ct.innerHTML = '<p class="placeholder">' + err.message + '</p>'; }
  }
  async function loadChapterInfinite(idx, restoreScroll) {
    state.chapterIndex = idx;
    const ch = state.catalog.chapters[idx];
    state.currentChapter = ch.file;
    const ct = document.getElementById('content');
    ct.className = 'reader' + (state.settings && state.settings.fading_edge ? ' fading-edge' : '');
    ct.innerHTML = '';
    ct.appendChild(buildReaderToolbar(ch));
    const body = el('div', { id: 'reader-body', class: 'infinite' });
    ct.appendChild(body);
    state.appendedIdx = -1;
    try {
      await appendChapter(idx);
      // Install initial sentinel at the end if more chapters remain
      if (state.appendedIdx < state.catalog.chapters.length - 1) {
        installSentinel();
      }
      highlightActiveChapter();
      if (typeof restoreScroll === 'number' && restoreScroll > 0) {
        ct.scrollTop = restoreScroll;
      } else {
        ct.scrollTop = 0;
      }
      updateProgressBar();
      updateReadingTime();
      if (state.scrollListener) ct.removeEventListener('scroll', state.scrollListener);
      state.scrollListener = () => {
        const info = activeChapterInfo();
        if (info.idx !== state.chapterIndex) {
          state.chapterIndex = info.idx;
          highlightActiveChapter();
          markReadChapters();
        }
        savePositionDebounced();
        updateProgressBar();
        updateReadingTime();
        resetIdleTimer();
      };
      ct.addEventListener('scroll', state.scrollListener);
      window.addEventListener('beforeunload', savePositionNow);
    } catch (err) { ct.innerHTML = '<p class="placeholder">' + err.message + '</p>'; }
  }
  async function appendChapter(idx) {
    if (!state.catalog || !state.catalog.chapters || !state.catalog.chapters[idx]) return false;
    if (idx <= state.appendedIdx) return false;
    // Serialize: chain onto the queue so concurrent callers can never
    // both pass the appendedIdx check and append the same chapter twice.
    const next = state.appendQueue.then(() => doAppendChapter(idx));
    state.appendQueue = next.catch(() => {});
    return next;
  }
  async function doAppendChapter(idx) {
    // Re-check inside the queue — a prior caller may have already done it.
    if (idx <= state.appendedIdx) return false;
    if (!state.catalog || !state.catalog.chapters[idx]) return false;
    const ch = state.catalog.chapters[idx];
    state.currentChapter = ch.file;
    const md = await api('/api/vault/' + encodeURIComponent(state.vault) +
                         '/book/' + encodeURIComponent(state.book) +
                         '/chapter/' + encodeURIComponent(ch.file));
    let html = mdToHtml(md);
    html = rewriteImgSrcs(html);
    const block = el('section', {
      class: 'chapter-block',
      'data-chapter-idx': String(idx),
      'data-chapter-file': ch.file,
    });
    block.appendChild(el('h2', { class: 'chapter-divider' }, ch.title || ch.file));
    const inner = el('div', { class: 'chapter-content' });
    inner.innerHTML = html;
    block.appendChild(inner);
    const body = document.getElementById('reader-body');
    if (!body) return false;
    // Remove any sentinels before appending so the new block sits at the end.
    body.querySelectorAll('.chapter-sentinel').forEach(s => s.remove());
    body.appendChild(block);
    state.appendedIdx = idx;
    // Apply highlights + update bookmarks for this chapter
    const hl = await HL.load(ch.file);
    HL.applyTo(block, hl);
    state.bookmarks = await BM.load(ch.file);
    renderBookmarksInSidebar();
    // NOTE: sentinel is installed by the CALLER (loadChapterInfinite
    // for the initial open, or the IO callback for auto-load). Doing
    // it here would race with the IO callback and create duplicate
    // sentinels → duplicate chapter blocks.
    return true;
  }
  function installSentinel() {
    const ct = document.getElementById('content');
    if (!ct || !state.catalog) return;
    if (state.appendedIdx >= state.catalog.chapters.length - 1) {
      appendEndCard();
      return;
    }
    const body = document.getElementById('reader-body');
    if (!body) return;
    const s = el('div', { class: 'chapter-sentinel' }, 'Loading next chapter\u2026');
    body.appendChild(s);
    const io = new IntersectionObserver((entries) => {
      if (!entries[0].isIntersecting) return;
      io.disconnect();
      s.remove();
      const next = state.appendedIdx + 1;
      if (next < state.catalog.chapters.length) {
        // Chain onto the queue so installSentinel-after-append runs in order.
        state.appendQueue = state.appendQueue
          .then(() => doAppendChapter(next))
          .then(() => { if (state.appendedIdx < state.catalog.chapters.length - 1) installSentinel(); })
          .catch(() => {});
      }
    }, { root: ct, rootMargin: '300px' });
    io.observe(s);
  }
  function activeChapterInfo() {
    const ct = document.getElementById('content');
    const blocks = ct ? ct.querySelectorAll('[data-chapter-idx]') : [];
    if (!blocks.length) return { idx: state.chapterIndex || 0, local: 0 };
    const viewTop = ct.getBoundingClientRect().top + 1;
    let activeIdx = state.chapterIndex || 0;
    for (const b of blocks) {
      if (b.getBoundingClientRect().bottom > viewTop) {
        activeIdx = parseInt(b.dataset.chapterIdx, 10);
        break;
      }
    }
    const block = ct.querySelector('[data-chapter-idx="' + activeIdx + '"]');
    const local = block ? Math.max(0, ct.scrollTop - block.offsetTop) : 0;
    return { idx: activeIdx, local: local };
  }
  function rewriteImgSrcs(html) {
    return html.replace(/<img\s+([^>]*?)src="([^"]+)"([^>]*)>/g, (m, pre, src, post) => {
      if (/^(https?:|data:|\/\/)/i.test(src)) return m;
      const newSrc = '/api/vault/' + encodeURIComponent(state.vault) +
                     '/image/' + encodeURIComponent(state.book) +
                     '/' + encodeURIComponent(src);
      return '<img ' + pre + 'src="' + newSrc + '"' + post + '>';
    });
  }
  function buildReaderToolbar(ch) {
    const bar = el('div', { class: 'toolbar' });
    const prev = el('button', { onclick: () => prevChapter() }, '\u2190');
    if (state.chapterIndex === 0) prev.disabled = true;
    const next = el('button', { onclick: () => nextChapter() }, '\u2192');
    if (state.chapterIndex === state.catalog.chapters.length - 1) next.disabled = true;
    const title = el('span', { class: 'chapter-title' }, ch.title || ch.file);
    const right = el('span', { class: 'toolbar-right' });
    const progressTxt = el('span', null, 'Ch ' + (state.chapterIndex + 1) + ' / ' + state.catalog.chapters.length);
    const timeEl = el('span', { id: 'reading-time' }, '');
    const bmBtn = el('button', { onclick: quickBookmark, title: 'Bookmark' }, '\u2606');
    right.appendChild(progressTxt);
    right.appendChild(timeEl);
    right.appendChild(bmBtn);
    bar.appendChild(prev); bar.appendChild(next);
    bar.appendChild(title); bar.appendChild(right);
    return bar;
  }
  function renderBookmarksInSidebar() {
    const list = document.querySelector('#sidebar .bm-list');
    const head = document.querySelector('#sidebar .bm-heading');
    if (!list || !head) return;
    if (!state.bookmarks.length) { head.style.display = 'none'; list.innerHTML = ''; return; }
    head.style.display = '';
    list.innerHTML = state.bookmarks.map(b =>
      '<a data-bm="' + escapeHtml(b.id) + '" data-anchor="' + b.anchor + '" data-chapter="' + escapeHtml(b.chapter) + '">' +
        escapeHtml(b.label) +
      '</a>'
    ).join('');
    list.querySelectorAll('a[data-bm]').forEach(a => {
      a.addEventListener('click', () => {
        const idx = state.catalog.chapters.findIndex(c => c.file === a.dataset.chapter);
        if (idx < 0) return;
        scrollToChapter(idx, parseInt(a.dataset.anchor, 10) || 0);
      });
      a.addEventListener('contextmenu', async (e) => {
        e.preventDefault();
        if (confirm('Delete bookmark "' + a.textContent + '"?')) {
          await BM.remove(a.dataset.bm);
          state.bookmarks = state.bookmarks.filter(x => x.id !== a.dataset.bm);
          renderBookmarksInSidebar();
        }
      });
    });
  }

  // ──────────────────────────────────────────────────────────────── //
  //  Boot                                                              //
  // ──────────────────────────────────────────────────────────────── //
  async function boot() {
    buildShell();
    bindKeyboard(); bindGestures();
    bindSelectionPopup(); bindMarkClicks(); bindImageZoom();
    bindClickToTurn(); bindIdleTimer();
    resetIdleTimer();
    try {
      const vaults = await api('/api/vaults');
      state.vaults = vaults;
      if (vaults.length === 0) {
        document.getElementById('content').innerHTML =
          '<p class="placeholder">No .vault files discovered in this directory.</p>';
      } else if (vaults.length === 1) {
        await selectVault(vaults[0].name);
      } else {
        renderVaults();
      }
    } catch (err) {
      document.getElementById('content').innerHTML = '<p class="placeholder">' + err.message + '</p>';
    }
  }
  boot();
})();
"""


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 9 — CLI: converter                                                 #
# ═══════════════════════════════════════════════════════════════════════════ #

def open_vault(vault_path: str, password: Optional[str]) -> VaultManager:
    """Open the vault, set or verify its password."""
    mgr = VaultManager(vault_path)
    if not _vault_has_assets(mgr) and not mgr.has_password():
        if password:
            mgr.set_password(password)
            log.info("Password set on new vault.")
        return mgr
    _verify_password(mgr, password)
    return mgr


def _verify_password(mgr: VaultManager, password: Optional[str]) -> None:
    if not mgr.has_password():
        return
    if password and mgr.check_password(password):
        return
    for _ in range(3):
        try:
            typed = getpass.getpass("Vault password: ")
        except (EOFError, KeyboardInterrupt):
            raise SystemExit("Aborted: password required.")
        if mgr.check_password(typed):
            return
        log.error("Incorrect password.")
    raise SystemExit("Aborted: password retries exhausted.")


def _vault_has_assets(mgr: VaultManager) -> bool:
    res = mgr.resolve_path(GLOBAL_CATALOG)
    return bool(res and res[0] == "asset")


def cli_convert(argv: List[str]) -> int:
    args = _build_convert_parser().parse_args(argv)
    _configure_logging(verbose=args.verbose)

    vault_path = args.vault if args.vault.endswith(".vault") else args.vault + ".vault"
    target     = args.epub_dir or args.epub_file
    try:
        epubs = collect_epubs(target, recursive=args.recursive)
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        return 1
    if not epubs:
        if os.path.isdir(target) and not args.recursive:
            log.error("No EPUB files found in %s (top-level only; pass --recursive to scan subfolders)", target)
        else:
            log.error("No EPUB files found in %s", target)
        return 1

    mgr = open_vault(vault_path, args.password)
    book_entries: List[Dict[str, object]] = []
    try:
        for epub in epubs:
            try:
                entry = process_epub(epub, mgr)
            except Exception as exc:
                log.error("Failed to process '%s': %s", epub, exc)
                continue
            if entry is not None:
                book_entries.append(entry)
    finally:
        if book_entries:
            _write_merged_global_catalog(mgr, book_entries)
        else:
            log.warning("No books were processed; skipping global catalog.")
        if args.rebuild_index:
            try:
                log.info("Rebuilding full-text search index...")
                mgr.rebuild_search_index()
            except Exception as exc:
                log.error("Search index rebuild failed: %s", exc)
        mgr.close()
        _truncate_vault_trailing_zeros(vault_path)

    log.info("Done. %d book(s) added to %s", len(book_entries), vault_path)
    return 0


def _truncate_vault_trailing_zeros(vault_path: str) -> None:
    """Drop trailing zero pages from a SQLite-backed vault file.

    SQLite's mmap'd writes can leave the file physically larger than the
    logical page count. Reading is unaffected (WORM data is intact), but
    the on-disk size is bigger than the actual content. We seek back from
    EOF and find the last non-zero page, then truncate.
    """
    page_size = 4096
    try:
        # Reopen briefly to learn the true page count.
        probe = sqlite3.connect(vault_path)
        page_count = probe.execute("PRAGMA page_count").fetchone()[0]
        probe.close()
        target_size = page_count * page_size
        with open(vault_path, "rb+") as f:
            f.seek(0, 2)
            current = f.tell()
            if current <= target_size:
                return
            # Read the tail to make sure it's all zeros before truncating.
            f.seek(target_size)
            tail = f.read(current - target_size)
            if any(tail):
                # Non-zero data in the trailing region — leave it alone.
                return
            f.truncate(target_size)
            log.info("Truncated %d trailing zero page(s) (%s -> %s).",
                     (current - target_size) // page_size,
                     format_size(current), format_size(target_size))
    except Exception as exc:
        log.debug("trailing-zero truncation skipped: %s", exc)


def _build_convert_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="epub2vault",
        description="Convert a folder of EPUB files into a single DenseVault archive.",
    )
    parser.add_argument("--vault", required=True, help="path to the .vault file")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--epub-dir",  metavar="DIR",  help="folder of EPUBs to ingest")
    group.add_argument("--epub-file", metavar="FILE", help="single EPUB to ingest")
    parser.add_argument("--password", default=None,
                        help="vault password (prompted if omitted)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="enable debug logging")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="recurse into subfolders of --epub-dir (default: top-level only)")
    parser.add_argument("--rebuild-index", action="store_true",
                        help="rebuild full-text search index after conversion")
    return parser


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 10 — CLI: reader                                                    #
# ═══════════════════════════════════════════════════════════════════════════ #

def cli_read(argv: List[str]) -> int:
    args = _build_read_parser().parse_args(argv)
    _configure_logging(verbose=args.verbose)

    root = os.getcwd()
    if args.vault:
        if not os.path.exists(args.vault):
            log.error("Vault not found: %s", args.vault)
            return 1
        vault_path = os.path.abspath(args.vault)
        root       = os.path.dirname(vault_path) or "."
        _open_vault(os.path.splitext(os.path.basename(vault_path))[0], vault_path)
    else:
        for name, path in discover_vaults(root):
            _open_vault(name, path)

    discovered = REGISTRY.all()
    if not discovered:
        log.error("No .vault files found. Pass --vault or place one in %s.", root)
        return 1
    log.info("Serving %d vault(s) on http://%s:%d", len(discovered), args.host, args.port)

    server = ThreadingReaderServer((args.host, args.port), ReaderHandler)
    if not args.no_browser:
        try:
            webbrowser.open(f"http://{args.host}:{args.port}/")
        except Exception as exc:
            log.warning("Could not open browser: %s", exc)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down…")
    finally:
        server.server_close()
    return 0


def _open_vault(name: str, path: str) -> None:
    try:
        REGISTRY.add(name, VaultManager(path))
        log.info("Opened vault: %s", path)
    except Exception as exc:
        log.error("Failed to open '%s': %s", path, exc)


def _build_read_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault_reader",
        description="Zero-dependency web reader for DenseVault libraries.",
    )
    parser.add_argument("--port", type=int, default=8080, help="HTTP port (default: 8080)")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--vault", help="path to a single .vault file (else scan cwd)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    return parser


# ═══════════════════════════════════════════════════════════════════════════ #
# SECTION 11 — Main entry: subcommand dispatch                               #
# ═══════════════════════════════════════════════════════════════════════════ #

def cli_index(argv: List[str]) -> int:
    """CLI entry point for ``smoltome.py index``."""
    args = _build_index_parser().parse_args(argv)
    _configure_logging(verbose=args.verbose)

    vault_path = args.vault if args.vault.endswith(".vault") else args.vault + ".vault"
    if not os.path.exists(vault_path):
        log.error("Vault not found: %s", args.vault)
        return 1

    mgr = open_vault(vault_path, args.password)
    try:
        mgr.rebuild_search_index()
    finally:
        mgr.close()
        _truncate_vault_trailing_zeros(vault_path)

    log.info("Search index rebuild complete.")
    return 0


def _build_index_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smoltome.py index",
        description="Rebuild the full-text search index for an existing vault.",
    )
    parser.add_argument("--vault", required=True, help="path to the .vault file")
    parser.add_argument("--password", default=None,
                        help="vault password (prompted if omitted)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="enable debug logging")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    # Auto-detect invocation as `epub2vault` or `vault_reader` (symlink/copy).
    base = os.path.basename(sys.argv[0]).lower()
    if base in ("epub2vault", "vault_reader"):
        argv = [base] + list(argv)

    if not argv or argv[0] in ("-h", "--help"):
        print("Usage: smoltome.py <command> [args]")
        print()
        print("Commands:")
        print("  convert   convert a folder of EPUBs into a .vault file")
        print("  read      serve books from one or more .vault files over HTTP")
        print("  index     rebuild the full-text search index for an existing vault")
        print()
        print("Run 'smoltome.py <command> --help' for command-specific options.")
        return 0

    cmd = argv[0]
    rest = argv[1:]
    if cmd == "convert":
        return cli_convert(rest)
    if cmd == "read":
        return cli_read(rest)
    if cmd == "index":
        return cli_index(rest)
    if cmd == "epub2vault":
        return cli_convert(rest)
    if cmd == "vault_reader":
        return cli_read(rest)

    print(f"Unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

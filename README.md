# smoltome

> **Single-file EPUB converter + zero-dependency web reader.**
> Turn a folder of ebooks into a deduplicated, compressed SQLite vault and read them in a browser with highlighting, bookmarks, infinite scroll, and 8 themes—no `pip install` required.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Converting EPUBs](#converting-epubs)
  - [Running the Reader](#running-the-reader)
  - [Makefile Shortcuts](#makefile-shortcuts)
- [The Vault Format](#the-vault-format)
- [Web Reader](#web-reader)
  - [Interface & Themes](#interface--themes)
  - [Reading Modes](#reading-modes)
  - [Annotations](#annotations)
  - [Keyboard & Gestures](#keyboard--gestures)
- [HTTP API](#http-api)
- [Security](#security)
- [Tips & Troubleshooting](#tips--troubleshooting)
- [License](#license)

---

## Overview

`smoltome.py` is a self-contained Python 3 script that does two things:

1. **Ingests** EPUB files into a `.vault` archive—an SQLite-based, content-addressed storage layer with adaptive compression and deduplication.
2. **Serves** those books over HTTP with a fully embedded single-page reader (HTML/CSS/JS baked into the Python file).

It works out of the box with standard EPUBs, but it is particularly pleasant for long, illustration-heavy serial fiction—light novels, web-fiction collections, and translated EPUBs that mix prose with inline images. The extraction pipeline preserves cover order, chapter spine sequence, and embedded illustrations exactly as they appear in the source file.

There are no external dependencies. The entire stack fits in one file and uses only the standard library. Requires Python 3.6+.

---

## Features

### Converter

- **EPUB → Markdown** extraction with OPF spine ordering and metadata parsing.
- **Content-Defined Chunking (CDC)** via gear-hash rolling window (64 KB min / 256 KB target / 1 MB max) so small edits to a file don’t invalidate downstream deduplication.
- **Adaptive compression**: samples Shannon entropy to decide whether zlib level-9 will actually save space; high-entropy data (already-compressed images, encrypted blobs) is stored raw.
- **BLAKE2b deduplication** across all books—identical chunks are stored once.
- **WORM semantics**: immutable assets; re-converting the same filename updates the catalog but does not duplicate chunks.
- **Global catalog merging**: incremental updates preserve previously-ingested books.
- **Password protection**: PBKDF2-HMAC-SHA256 with per-vault salt.

### Reader

- **Zero-dependency HTTP server** (`ThreadingHTTPServer`) with connection pooling and WAL-tuned SQLite.
- **8 built-in themes**: default-light, default-dark, sepia, paper, solarised-light, solarised-dark, oled-black, high-contrast.
- **Infinite scroll** or chapter-by-chapter paging—ideal for binge-reading multi-volume series.
- **Text highlights** in 4 colors with optional notes.
- **Per-chapter bookmarks** with one-click save.
- **Reading position** auto-persisted (chapter index + scroll offset).
- **Progress bar** and live reading-time estimation.
- **In-chapter search** with regex-safe highlighting and prev/next navigation.
- **Image zoom** modal for inline illustrations and maps.
- **Zen mode** (auto-hiding chrome) and click-to-turn page regions.
- **Mobile swipe gestures** (chapter navigation + pull-down settings).
- **Sidebar** with chapter list, read-state indicators, and bookmark list.

---

## Architecture

| Layer           | Technology            | Details                                                                             |
| --------------- | --------------------- | ----------------------------------------------------------------------------------- |
| **Storage**     | SQLite + WAL          | `PRAGMA mmap_size = 512 MB`, 64 MB page cache, memory temp store                    |
| **Chunking**    | Gear-hash CDC         | splitmix64 gear table, 14-bit / 19-bit masks for size biasing                       |
| **Compression** | Entropy-adaptive zlib | Sampled 2 KB stratified; thresholds at 4.0 and 7.5 bits/byte                        |
| **Hashing**     | BLAKE2b (256-bit)     | Content-addressed dedup in `chunks` table                                           |
| **Paths**       | WebDAV-style          | `/project/collection/asset` with implicit `_GENERAL` and `_ROOT` containers         |
| **Server**      | `ThreadingHTTPServer` | Daemon threads, reuse_address, basic auth gate                                      |
| **Client**      | Vanilla JS SPA        | Embedded in `INDEX_HTML`, `INDEX_CSS`, `INDEX_JS` strings                           |
| **User Data**   | Sidecar JSON          | `.notes.json` per vault: settings, positions, bookmarks, highlights, search history |

---

## Quick Start

```bash
# 1. Grab the script
curl -O https://raw.githubusercontent.com/smolfiddle/smoltome/main/smoltome.py
chmod +x smoltome.py

# 2. Convert all EPUBs in the current directory
python3 smoltome.py convert --vault library.vault --epub-dir .

# 3. Start the reader
python3 smoltome.py read --vault library.vault --port 8080

# 4. Open http://localhost:8080
```

---

## Usage

### Converting EPUBs

```bash
# Directory (top-level only)
python3 smoltome.py convert --vault library.vault --epub-dir ./books

# Recursive scan
python3 smoltome.py convert --vault library.vault --epub-dir ./books --recursive

# Single file
python3 smoltome.py convert --vault library.vault --epub-file ./book.epub

# Password-protect a new vault
python3 smoltome.py convert --vault library.vault --epub-dir . --password "secret"
```

If the script is symlinked or copied to `epub2vault`, it automatically runs the `convert` subcommand:

```bash
ln -s smoltome.py epub2vault
./epub2vault --vault library.vault --epub-dir .
```

### Running the Reader

```bash
# Serve a specific vault
python3 smoltome.py read --vault library.vault --port 8080

# Auto-scan current directory for any .vault file
python3 smoltome.py read --port 8080

# Bind to all interfaces
python3 smoltome.py read --host 0.0.0.0 --port 8080

# Do not auto-open browser
python3 smoltome.py read --no-browser
```

If the script is symlinked to `vault_reader`, it automatically runs the `read` subcommand.

### Rebuilding Search Index

```bash
# Rebuild full-text search index for an existing vault
python3 smoltome.py index --vault library.vault

# With password
python3 smoltome.py index --vault library.vault --password "secret"
```

### Makefile Shortcuts

A `Makefile` is provided for directory-local workflows:

| Command        | What it does                                                            |
| -------------- | ----------------------------------------------------------------------- |
| `make convert` | Finds `*.epub` in cwd and packs them into `library.vault`               |
| `make serve`   | Finds the first `*.vault` in cwd and launches the reader on port `8080` |
| `make clean`   | Removes `__pycache__`, `.mypy_cache`, and `*.pyc` files                 |

---

## The Vault Format

A `.vault` file is an SQLite database with the following schema:

```sql
vault_properties  -- key/value store (password salt/hash)
projects          -- top-level namespaces
collections       -- directories (nested via parent_id)
assets            -- file records with JSON manifests
metadata          -- key/value tags per asset (filename, size, root_hash)
chunks            -- deduplicated, optionally compressed blob store
```

### Asset Manifest (JSON)

When a book is ingested, each chapter and image becomes an asset. The manifest tracks:

```json
{
  "version": 3,
  "filename": "01_chapter_one.md",
  "total_size": 15234,
  "chunks": ["a1b2c3...", "d4e5f6..."],
  "chunk_sizes": [15234],
  "chunk_offsets": [0],
  "root_hash": "deadbeef...",
  "compression": {
    "original_size": 15234,
    "stored_size": 8912,
    "ratio": 1.71,
    "compressed_chunks": 1,
    "raw_chunks": 0
  }
}
```

### Catalogs

- **Per-book**: `/books/{book_id}/catalog.json` — metadata, chapter list, image list, cover.
- **Global**: `/catalog_root.json` — merged index of all books in the vault. Incremental converts update this without dropping existing entries.

### Sidecar File

Reader state lives in a sibling `.notes.json` file (e.g., `library.notes.json`). It is human-readable, atomically written (temp + `os.replace`), and contains:

- `settings` — theme, typography, layout
- `positions` — last-read chapter & scroll per book
- `bookmarks` — per-chapter labeled anchors
- `highlights` — per-chapter color-coded ranges with notes
- `searches` — MRU search history (cap 50)

---

## Web Reader

### Interface & Themes

The reader is a responsive SPA that works on desktop and mobile. Choose from **8 themes**:

| #   | Theme             | Best for             |
| --- | ----------------- | -------------------- |
| 1   | `default-light`   | Daytime reading      |
| 2   | `default-dark`    | General dark mode    |
| 3   | `sepia`           | Low eye strain       |
| 4   | `paper`           | Print-like aesthetic |
| 5   | `solarised-light` | Code/text clarity    |
| 6   | `solarised-dark`  | Terminal aesthetic   |
| 7   | `oled-black`      | OLED power saving    |
| 8   | `high-contrast`   | Accessibility        |

Typography controls include font family (system / serif / mono), font size (12–32 px), line height, margin, alignment, max width, and paragraph indent. The defaults are tuned for long-form prose: a comfortable 18 px size, 1.6 line height, and generous margins that keep line lengths readable even when flipping through dialogue-heavy chapters.

### Reading Modes

- **Chapter mode**: Navigate with ← / → toolbar buttons. Each chapter loads independently.
- **Infinite scroll**: Chapters append automatically as you scroll. A sentinel triggers the next load 300 px before the viewport bottom. An end-of-book card appears at the finish.

### Annotations

- **Highlight**: Select text → a popup appears with 4 color swatches. Click a highlight to edit its note or delete it.
- **Bookmark**: Press `b` or the toolbar star to save the current scroll position with the chapter title as the label. Right-click (or long-press) a bookmark in the sidebar to delete it.

### Keyboard & Gestures

| Key                       | Action                         |
| ------------------------- | ------------------------------ |
| `↑` / `↓`                 | Scroll one line                |
| `←` / `→`                 | Scroll one page                |
| `Shift + ←` / `Shift + →` | Previous / next chapter        |
| `Space` / `PgUp` / `PgDn` | Page scroll                    |
| `Home` / `End`            | Chapter start / end            |
| `/`                       | Open in-chapter search         |
| `b`                       | Quick bookmark                 |
| `1` – `8`                 | Instant theme switch           |
| `,`                       | Open settings                  |
| `?`                       | Show shortcut overlay          |
| `Esc`                     | Close panels / toggle zen mode |

**Mobile:**

- Swipe left → next chapter
- Swipe right → previous chapter
- Swipe down from top edge → open settings

---

## HTTP API

The reader communicates with the backend over a small REST API.

| Method           | Endpoint                                    | Description                   |
| ---------------- | ------------------------------------------- | ----------------------------- |
| `GET`            | `/api/vaults`                               | List discovered vaults        |
| `GET`            | `/api/vault/{v}/books`                      | List all books                |
| `GET`            | `/api/vault/{v}/book/{id}/catalog`          | Book metadata & chapter index |
| `GET`            | `/api/vault/{v}/book/{id}/chapter/{file}`   | Raw Markdown chapter          |
| `GET`            | `/api/vault/{v}/image/{book}/{file}`        | Image asset (cached 1 hr)     |
| `GET`            | `/api/vault/{v}/search?q=...`               | Title/author + full-text content search |
| `GET` / `PUT`    | `/api/vault/{v}/settings`                   | Reader settings               |
| `GET` / `PUT`    | `/api/vault/{v}/book/{id}/position`         | Reading position              |
| `GET` / `POST`   | `/api/vault/{v}/book/{id}/bookmarks`        | List / create bookmarks       |
| `DELETE`         | `/api/vault/{v}/book/{id}/bookmarks/{bid}`  | Delete bookmark               |
| `GET` / `POST`   | `/api/vault/{v}/book/{id}/highlights`       | List / create highlights      |
| `PUT` / `DELETE` | `/api/vault/{v}/book/{id}/highlights/{hid}` | Update / delete highlight     |

Password-protected vaults require `Authorization: Basic` with any username and the vault password.

---

## Security

- **Password hashing**: PBKDF2-HMAC-SHA256, 100,000 iterations, 16-byte random salt.
- **Auth**: HTTP Basic Auth over the local reader connection. The password is checked against the vault hash; no username is required.
- **WORM**: Assets are immutable. The converter will not overwrite primary content; it only adds new chunks and updates catalog pointers.

---

## Tips & Troubleshooting

**Cover images not detected**
The parser checks EPUB 2/3 `<meta name="cover">` tags, then falls back to the first image whose filename contains `cover`. Most fan-translated and retail light-novel EPUBs name their cover `Cover.jpg` or `cover.png`, so this catches them even when the OPF meta tag is missing.

**Inline illustrations not showing**
The reader rewrites relative `<img src="...">` paths to vault API paths automatically. If an image is missing, check that it was listed in the EPUB’s OPF manifest and that its MIME type starts with `image/`.

**Converting the same book twice**
The global catalog merges entries by `book_id`. Re-converting updates the catalog but reuses existing deduplicated chunks, so storage cost is minimal—useful when you re-download a corrected volume and want to replace the old copy in-place.

**Password prompt during convert**
If the vault already has a password, the CLI will prompt up to 3 times. Use `--password` to provide it non-interactively.

**Truncating zero pages**
After conversion, the tool attempts to trim trailing zero pages from the SQLite file to keep the on-disk size tight. This is safe and purely cosmetic.

**Large illustration-heavy books**
Because images are stored as deduplicated chunks, a series that reuses the same cover or insert art across volumes will only store those bytes once. The vault remains compact even when you archive dozens of volumes.

---

## License

[MIT](LICENSE)

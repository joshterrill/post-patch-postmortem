# Patch Tuesday Analyzer

CLI for Microsoft Patch Tuesday research:
- Fetch MSRC patch/CVE metadata
- Download and extract update packages
- Pull pre-patch binaries from Winbindex
- Diff pre/post binaries with BinDiff
- Generate HTML reports (including optional Ghidra pseudo-C unified diffs)

## Installation

```bash
pip install -e .
```

Recommended system dependencies:
- `cabextract` (for extracting `.cab`/`.msu` contents on macOS/Linux)
  - macOS: `brew install cabextract`
  - Debian/Ubuntu: `sudo apt install cabextract`

BinDiff pipeline dependencies:
- [Ghidra](https://ghidra-sre.org/)
- [BinExport Ghidra extension](https://github.com/google/binexport/releases)
- [BinDiff](https://github.com/google/bindiff/releases)

Optional environment variables:
- `GHIDRA_HOME` (path to Ghidra install)
- `BINDIFF_HOME` (path to BinDiff install root)

## Quick Start

1. Fetch latest Patch Tuesday metadata:

```bash
patch-tuesday fetch
patch-tuesday updates
patch-tuesday list -d 2026-02
```

2. Full KB workflow (download -> extract -> baseline -> compare):

```bash
patch-tuesday download KB5034441
patch-tuesday extract KB5034441
patch-tuesday baseline KB5034441
patch-tuesday bindiff KB5034441 --report
```

3. Binary-targeted diff directly from Winbindex:

```bash
patch-tuesday versions notepad.exe -a x64
patch-tuesday binary-diff notepad.exe --new-date 2026-02-10 --old-date 2025-12-01 --report
```

4. Include decompiled pseudo-C git-style diffs in report:

```bash
patch-tuesday binary-diff notepad.exe --new-date 2026-02-10 --old-date 2025-12-01 --pseudo-c
```

## Command Reference

### `fetch`
Fetch Patch Tuesday data from MSRC.

```bash
patch-tuesday fetch [OPTIONS]
```

Options:
- `-d, --date TEXT` specific month (`YYYY-MM`)
- `-n, --count INTEGER` number of recent updates (default: `1`)
- `-v, --verbose` verbose output
- `--source [rss|api]` source for latest update IDs (default: `rss`)

Examples:
```bash
patch-tuesday fetch
patch-tuesday fetch -n 3
patch-tuesday fetch -d 2026-02
patch-tuesday fetch --source api
```

### `updates`
List available update IDs.

```bash
patch-tuesday updates [OPTIONS]
```

Options:
- `-y, --year INTEGER`
- `--source [rss|api]` (default: `rss`)

### `list`
List patches in local DB.

```bash
patch-tuesday list [OPTIONS]
```

Options:
- `-d, --date TEXT` month filter (`YYYY-MM`)
- `-p, --product TEXT` product substring
- `-s, --severity [critical|important|moderate|low]`

### `show`
Show details for one KB.

```bash
patch-tuesday show KB_NUMBER
```

### `stats`
Show DB statistics.

```bash
patch-tuesday stats
```

### `download`
Download update packages from Microsoft Update Catalog.

```bash
patch-tuesday download KB_NUMBER [OPTIONS]
```

Options:
- `-a, --arch [x64|x86|arm64]`
- `-l, --list-only`

### `extract`
Extract binaries from downloaded packages.

```bash
patch-tuesday extract KB_NUMBER [OPTIONS]
```

Options:
- `-s, --save-db` save extracted file metadata to DB

### `files`
List extracted files for a KB.

```bash
patch-tuesday files KB_NUMBER
```

### `baseline`
Fetch pre-patch versions for extracted binaries (Winbindex).

```bash
patch-tuesday baseline KB_NUMBER
```

### `diff`
Show changed files with pre/post paths.

```bash
patch-tuesday diff KB_NUMBER
```

### `versions`
List available Winbindex versions for a binary.

```bash
patch-tuesday versions FILENAME [OPTIONS]
```

Options:
- `-a, --arch [x64|x86|arm64]`

### `binary-diff`
Directly compare two versions of one binary from Winbindex.

```bash
patch-tuesday binary-diff FILENAME [OPTIONS]
```

Options:
- `-a, --arch [x64|x86|arm64]` (default: `x64`)
- `--new-version TEXT`
- `--old-version TEXT`
- `--new-build TEXT`
- `--old-build TEXT`
- `--new-date TEXT` (`YYYY-MM-DD`)
- `--old-date TEXT` (`YYYY-MM-DD`)
- `--limit INTEGER` Winbindex entries to inspect (default: `200`)
- `-l, --list-only` show selected pair only
- `--report` generate HTML report
- `--pseudo-c` include Ghidra pseudo-C unified diffs in report (implies `--report`)
- `--overwrite` force regeneration of cached exports/BinDiff/report for the selected pair

Cache behavior:
- Reuses existing downloaded binaries if already present.
- Reuses existing `.BinExport` files for the selected old/new pair.
- Reuses existing pair-specific `.BinDiff` database and HTML report when present.
- Use `--overwrite` to regenerate those artifacts on rerun.

Examples:
```bash
patch-tuesday binary-diff notepad.exe
patch-tuesday binary-diff notepad.exe -a x64 --list-only
patch-tuesday binary-diff notepad.exe --new-version "11.2501.31.0" --old-version "11.2312.18.0"
patch-tuesday binary-diff notepad.exe --new-date 2026-02-10 --old-date 2025-12-01 --report
patch-tuesday binary-diff notepad.exe --new-date 2026-02-10 --old-date 2025-12-01 --pseudo-c
```

### `cve`
Resolve CVE -> KBs and run pipeline.

```bash
patch-tuesday cve CVE_ID [OPTIONS]
```

Options:
- `-a, --arch [x64|x86|arm64]` catalog architecture filter
- `--fetch-count INTEGER` fallback fetch window when CVE not in DB (default: `24`)
- `-l, --list-only` resolve/list KBs only
- `--run-bindiff` run BinDiff stage after baseline
- `--report` generate reports for created BinDiff DBs
- `--pseudo-c` include Ghidra pseudo-C unified diffs in reports (implies `--report`)
- `-s, --save-db` persist extracted/baseline records

Examples:
```bash
patch-tuesday cve CVE-2026-20841 -l
patch-tuesday cve CVE-2026-20841 --run-bindiff --report
patch-tuesday cve CVE-2026-20841 --run-bindiff --pseudo-c
```

### `bindiff`
Compare pre/post binaries for a KB.

```bash
patch-tuesday bindiff KB_NUMBER [OPTIONS]
```

Options:
- `--check-deps` dependency check (Ghidra/BinDiff/BinExport)
- `--manual` print manual BinExport workflow
- `--run-diff` run BinDiff on existing `.BinExport` files
- `-b, --binary TEXT` restrict to one binary base name
- `--report` generate report(s)
- `--pseudo-c` include Ghidra pseudo-C unified diffs in report(s) (implies `--report`)

Examples:
```bash
patch-tuesday bindiff KB5034441 --check-deps
patch-tuesday bindiff KB5034441
patch-tuesday bindiff KB5034441 -b notepad.exe --report
patch-tuesday bindiff KB5034441 -b notepad.exe --pseudo-c
patch-tuesday bindiff KB5034441 --manual
patch-tuesday bindiff KB5034441 --run-diff --report
```

Note:
- `--pseudo-c` in `bindiff --run-diff` mode is ignored because only `.BinExport` files are available there, not original binaries.

### `clean`
Clear local DB/cache.

```bash
patch-tuesday clean [OPTIONS]
```

Options:
- `--db` clear DB
- `--cache` clear downloaded data
- `--all` clear DB + cache
- `-f, --force` no prompt

## End-to-End Workflows

### Workflow A: Patch Tuesday Month -> Binary Diff

```bash
patch-tuesday fetch -d 2026-02
patch-tuesday list -d 2026-02
patch-tuesday show KBxxxxxxx
patch-tuesday download KBxxxxxxx -a x64
patch-tuesday extract KBxxxxxxx
patch-tuesday baseline KBxxxxxxx
patch-tuesday diff KBxxxxxxx
patch-tuesday bindiff KBxxxxxxx -b notepad.exe --pseudo-c
```

### Workflow B: CVE -> KB -> BinDiff Report

```bash
patch-tuesday cve CVE-2026-20841 --run-bindiff --pseudo-c
```

This does:
1. Resolve CVE to one or more KBs
2. Download packages
3. Extract patched binaries
4. Fetch baseline binaries
5. Run BinDiff
6. Write HTML report(s), including optional pseudo-C unified diffs

### Workflow C: Single Binary Across Releases (Winbindex)

```bash
patch-tuesday versions notepad.exe -a x64
patch-tuesday binary-diff notepad.exe --new-date 2026-02-10 --old-date 2025-12-01 --pseudo-c
```

## Reports and Output Paths

Default output root:
- `downloads/bindiff/`

Typical paths:
- Binary-diff flow:
  - Downloads: `downloads/bindiff/binary/<binary>/downloads/`
  - BinExport: `downloads/bindiff/binary/<binary>/exports/`
  - HTML report: `downloads/bindiff/binary/<binary>/reports/`
- KB flow:
  - BinDiff DBs: `downloads/bindiff/KBxxxxxxx/exports/`
  - Reports: `downloads/bindiff/KBxxxxxxx/reports/`

Report behavior:
- Matched-functions table supports click-sort on every column.
- Matched-functions table includes all matched rows and renders via shadow-DOM pagination (30 rows/page), so sorting is global across the full dataset.
- With `--pseudo-c`, each matched row has a `View` action that opens a modal showing:
  - Function-level pseudo-C unified diff (`---/+++`)
  - One-hop call-graph context (callers/callees on primary and secondary sides)
  - Jump actions to open related rows/diffs from that context
- Pseudo-C is generated for all matched rows whose similarity is below 100%.

## Local Data Layout

```text
data/patches.db
downloads/packages/
downloads/extracted/
downloads/baseline/
downloads/bindiff/
```

## Troubleshooting

- "No KB mappings found for CVE":
  - Run `patch-tuesday fetch -d YYYY-MM`, then retry.
- "No baseline files found":
  - Run `patch-tuesday baseline KBxxxxxxx`.
- BinDiff dependencies missing:
  - Run `patch-tuesday bindiff KBxxxxxxx --check-deps`.
- Pseudo-C section missing in report:
  - Ensure `--pseudo-c` is used and Ghidra decompilation succeeds for selected matched functions.

## License

MIT

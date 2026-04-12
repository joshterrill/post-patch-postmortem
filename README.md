# Post-patch Postmortem

`ppp` is a CLI tool that allows you to analyze Microsoft Patch Tuesday updates. It provides a way of downloading binaries from an update or KB, diffing them with the previous version, and generating a BinDiff file and HTML report with pseudo-code diffing and function matching statistics.

*Shout out to [Winbindex](https://winbindex.m417z.com/) for making it easy to find and download specific versions of Windows binaries.*

The main root commands are:

- `fetch`: load Patch Tuesday metadata from MSRC
- `list`: list KBs for a month
- `show`: inspect one KB
- `lookup`: look up KBs for a CVE or history for a binary
- `analyze`: generate BinDiff artifacts for a month, KB, CVE, or file
- `clean`: clear local state

The supported entry points are:

- entire Patch Tuesday month
- specific KB
- specific binary
- optional CVE lookup to discover KBs first

## Installation

```bash
pip install -e .
```

Required / recommended external tools:

- `cabextract` for extracting `.cab` / `.msu` packages on macOS or Linux
- [Ghidra](https://ghidra-sre.org/)
- [BinExport Ghidra extension](https://github.com/google/binexport/releases)
- [BinDiff](https://github.com/google/bindiff/releases)

Optional environment variables:

- `GHIDRA_HOME`
- `BINDIFF_HOME`

## Quick Start

Fetch one month of metadata:

```bash
ppp fetch -d 2024-08
ppp list -d 2024-08
```

Analyze one KB:

```bash
ppp analyze kb KB5041578
```

Analyze one binary from Winbindex:

```bash
ppp lookup file tcpip.sys -a x64 --limit 150
ppp analyze file tcpip.sys -a x64 --kb KB5041578
```

Analyze an entire Patch Tuesday month:

```bash
ppp analyze month 2024-08
```

Resolve a CVE to KBs, then analyze:

```bash
ppp lookup cve CVE-2024-38063
ppp analyze cve CVE-2024-38063
```

## Main Workflows

### 1. Entire Patch Tuesday Month

Use this when you want all KBs in a month processed end to end.

```bash
ppp fetch -d 2024-08
ppp list -d 2024-08
ppp analyze month 2024-08
```

### 2. Specific KB

Use this when you already know the KB you want.

```bash
ppp show KB5041578
ppp analyze kb KB5041578
```

This workflow:

- downloads update packages when available
- extracts patched binaries
- fetches the most recent previous version for each matched binary
- generates BinExport files with Ghidra
- generates `.BinDiff` databases and HTML reports

### 3. Specific Binary

Use this when you care about one file rather than the whole KB.

List file history first:

```bash
ppp lookup file tcpip.sys -a x64 --limit 150
```

Then analyze that file:

```bash
ppp analyze file tcpip.sys -a x64 --kb KB5041578
```

Useful variant:

- omit `--kb` to compare the latest version against the most recent previous distinct version

Preview the selected pair without running Ghidra / BinDiff:

```bash
ppp analyze file tcpip.sys -a x64 --kb KB5041578 -l
```

### 4. CVE First

Use this when you start with a CVE and need to discover KBs first.

```bash
ppp lookup cve CVE-2024-38063
ppp analyze cve CVE-2024-38063
```

If the CVE is missing locally:

```bash
ppp lookup cve CVE-2024-38063 --fetch-count 24
```

## Output

Artifacts are written under `downloads/`.

Common paths:

- file workflow: `downloads/bindiff/binary/<file>/`
- KB workflow: `downloads/bindiff/KBxxxxxxx/`
- month workflow: one KB directory per analyzed patch

Important outputs:

- `.BinDiff` files: open in BinDiff
- `.html` reports: open in a browser

## Command Summary

Top-level help:

```bash
ppp --help
```

Lookup help:

```bash
ppp lookup --help
```

Analyze help:

```bash
ppp analyze --help
```

## Troubleshooting

- No KBs for a CVE:
  `ppp fetch -d YYYY-MM`, then retry `lookup cve`
- No package download for a KB:
  prefer the file workflow through `lookup file` and `analyze file`

## License

MIT

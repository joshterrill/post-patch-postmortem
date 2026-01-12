# Post Patch Postmortem

A CLI tool for analyzing Microsoft Patch Tuesday security updates. Fetches patch data from MSRC, downloads update packages, extracts binaries, and compares pre/post-patch versions using BinDiff.

## Installation

```bash
pip install -e .
```

For binary extraction on non-Windows: `brew install cabextract` (macOS) or `apt install cabextract` (Linux)

For BinDiff comparisons: [Ghidra](https://ghidra-sre.org/) + [BinExport extension](https://github.com/google/binexport/releases) + [BinDiff](https://github.com/google/bindiff/releases)

## Usage

### Fetch Patch Data

```bash
patch-tuesday fetch                    # Latest update
patch-tuesday fetch -n 3               # Last 3 updates
patch-tuesday fetch -d 2024-01         # Specific month
```

### Browse Updates

```bash
patch-tuesday updates                  # List available MSRC updates
patch-tuesday updates -y 2024          # Filter by year
patch-tuesday stats                    # Database statistics
```

### List & View Patches

```bash
patch-tuesday list                     # All patches
patch-tuesday list -d 2024-01          # By date
patch-tuesday list -p "Windows 11"     # By product
patch-tuesday list -s critical         # By severity
patch-tuesday show KB5034441           # Patch details
```

### Download & Extract

```bash
patch-tuesday download KB5034441       # Download MSU packages
patch-tuesday download KB5034441 -l    # List available packages
patch-tuesday download KB5034441 -a x64
patch-tuesday extract KB5034441        # Extract binaries from packages
patch-tuesday files KB5034441          # List extracted files
```

### Baseline & Diff

```bash
patch-tuesday baseline KB5034441       # Fetch pre-patch versions from WinBIndex
patch-tuesday versions ntdll.dll       # Show available versions of a binary
patch-tuesday diff KB5034441           # Show changed files with paths
```

### BinDiff Comparison

```bash
patch-tuesday bindiff KB5034441 --check-deps   # Check Ghidra/BinDiff installation
patch-tuesday bindiff KB5034441 --manual       # Instructions for manual export
patch-tuesday bindiff KB5034441 --run-diff     # Run BinDiff on exported files
patch-tuesday bindiff KB5034441                # Automatic comparison
```

## Data Storage

```
data/patches.db           # SQLite database
downloads/packages/       # MSU/CAB files
downloads/extracted/      # Post-patch binaries
downloads/baseline/       # Pre-patch binaries
downloads/bindiff/        # BinDiff outputs and reports
```

## License

MIT

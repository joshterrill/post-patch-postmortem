import re

from .models import WinBIndexFile


def humanize_windows_version_code(value: str) -> str:
    text = value.strip()
    if not text:
        return text

    if text.lower().startswith("windows "):
        return text

    match = re.match(r"^(10|11)-(.+)$", text, re.IGNORECASE)
    if match:
        family, version = match.groups()
        return f"Windows {family} {version.upper()}"

    match = re.match(r"^server-(.+)$", text, re.IGNORECASE)
    if match:
        return f"Windows Server {match.group(1).upper()}"

    match = re.match(r"^azurestackhci-(.+)$", text, re.IGNORECASE)
    if match:
        return f"Azure Stack HCI {match.group(1).upper()}"

    if re.match(r"^\d{4}$", text):
        return f"Windows 10 {text}"

    if re.match(r"^\d{2}h\d$", text, re.IGNORECASE):
        return f"Windows 10 {text.upper()}"

    return text


def format_windows_version_value(value: str) -> str:
    friendly = humanize_windows_version_code(value)
    if not friendly or friendly == value:
        return value
    return f"{value} ({friendly})"


def entry_windows_versions(entry: WinBIndexFile) -> list[str]:
    return sorted(
        {
            update.windows_version
            for update in getattr(entry, "updates", [])
            if getattr(update, "windows_version", None)
        }
    )


def matches_windows_version_filter(entry: WinBIndexFile, window_version: str | None) -> bool:
    if not window_version:
        return True

    needle = window_version.strip().lower()
    if not needle:
        return True

    for value in entry_windows_versions(entry):
        friendly = humanize_windows_version_code(value)
        display = format_windows_version_value(value)
        if needle in value.lower() or needle in friendly.lower() or needle in display.lower():
            return True

    return False

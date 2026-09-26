from pathlib import Path

MAX_BYTES = 200_000
_ILLEGAL_CHARS = '<>:"/\\|?*'


def _os_safe_name(name: str) -> str:
    cleaned = "".join("_" if ch in _ILLEGAL_CHARS else ch for ch in name)
    cleaned = cleaned.rstrip(" .")
    return cleaned or "unnamed"


def store_literal_attachment(root: Path, filename: str, content: str) -> str:
    """Save content under the filename as a literal string. No templates, no paths."""
    raw_name = filename.replace("\\", "/").split("/")[-1].strip()
    if not raw_name or raw_name in {".", ".."}:
        return "Rejected: empty or invalid filename."

    stored_name = _os_safe_name(raw_name)
    dest_dir = root.resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = (dest_dir / stored_name).resolve()
    if dest.parent != dest_dir:
        return "Rejected: filename must not escape the attachments folder."

    data = content.encode("utf-8")
    if len(data) > MAX_BYTES:
        return f"Rejected: attachment larger than {MAX_BYTES} bytes."

    try:
        dest.write_bytes(data)
    except OSError as exc:
        return f"Rejected: could not write filename as text ({exc}). Expression syntax was not evaluated."

    note = ""
    if stored_name != raw_name:
        note = f" OS-illegal characters were replaced for storage; original name kept as text: {raw_name}."
    return (
        f"Stored as a literal filename: {stored_name} ({len(data)} bytes).{note} "
        "Any template or expression characters in the name were not evaluated."
    )

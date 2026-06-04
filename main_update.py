from __future__ import annotations

import html
import json
import re
import shutil
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent
POSTS_DIR = ROOT / "_posts"
LEA_DIR = POSTS_DIR / "LEA"
NAV_PATH = ROOT / "nav.json"
TIMELINE_PATH = LEA_DIR / "Timeline.md"

NoteEntry = dict[str, object]
NotesIndex = dict[str, list[NoteEntry]]

PAGE_DEFINITIONS = [
    {
        "filename": "index.md",
        "title": "Overview",
    },
    {
        "filename": "Timeline.md",
        "title": "Timeline",
    },
]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def split_frontmatter(content: str) -> tuple[dict[str, str], str, bool]:
    text = content.lstrip("\ufeff\r\n")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text, False

    metadata: dict[str, str] = {}
    end_index = None

    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end_index = index
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"').strip("'")

    if end_index is None:
        return {}, text, False

    body = "\n".join(lines[end_index + 1 :]).lstrip("\n")
    return metadata, body, True


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def datetime_to_json(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def to_web_path(path: Path) -> str:
    return f"./{path.relative_to(ROOT).as_posix()}"


def to_web_dir(path: Path) -> str:
    relative = path.relative_to(ROOT).as_posix().rstrip("/")
    return f"./{relative}/"


def infer_date_from_slug(slug: str) -> datetime | None:
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})", slug)
    if not match:
        return None
    try:
        return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def resolve_note_file(note_dir: Path) -> Path | None:
    preferred = note_dir / f"{note_dir.name}.md"
    if preferred.exists():
        return preferred

    markdown_files = sorted(note_dir.glob("*.md"))
    if len(markdown_files) == 1:
        return markdown_files[0]
    if markdown_files:
        return markdown_files[0]
    return None


def build_note_entry(note_root: Path, note_file: Path, slug: str) -> tuple[NoteEntry, bool]:
    metadata, _body, has_metadata = split_frontmatter(read_text(note_file))
    title = metadata.get("title") or slug
    date_value = parse_datetime(metadata.get("date")) or infer_date_from_slug(slug)
    include_in_timeline = has_metadata and date_value is not None

    return (
        {
            "title": title,
            "slug": slug,
            "note_root": to_web_dir(note_root),
            "note_src": to_web_path(note_file),
            "date": datetime_to_json(date_value),
        },
        include_in_timeline,
    )


def category_sort_key(name: str) -> tuple[int, int | str]:
    match = re.match(r"^(\d{4})-writeups$", name)
    if match:
        return (0, -int(match.group(1)))
    return (1, name.lower())


def note_sort_key(note: NoteEntry) -> str:
    return str(note.get("date") or "")


def append_note(
    notes: list[NoteEntry],
    timeline_notes: list[NoteEntry],
    note_root: Path,
    note_file: Path,
    slug: str,
) -> None:
    note, include_in_timeline = build_note_entry(note_root, note_file, slug)
    notes.append(note)
    if include_in_timeline:
        timeline_notes.append(note)


def build_notes_index() -> tuple[NotesIndex, list[NoteEntry]]:
    notes_index: NotesIndex = {}
    timeline_notes: list[NoteEntry] = []

    category_dirs = [path for path in POSTS_DIR.iterdir() if path.is_dir() and path.name != "LEA"]
    for category_dir in sorted(category_dirs, key=lambda path: category_sort_key(path.name)):
        notes: list[NoteEntry] = []

        for entry in sorted(category_dir.iterdir(), key=lambda path: path.name.lower()):
            if entry.is_dir():
                note_file = resolve_note_file(entry)
                if not note_file:
                    continue
                append_note(notes, timeline_notes, entry, note_file, entry.name)
                continue

            if entry.is_file() and entry.suffix.lower() == ".md":
                append_note(notes, timeline_notes, category_dir, entry, entry.stem)

        notes.sort(key=note_sort_key, reverse=True)
        notes_index[category_dir.name] = notes

    return notes_index, timeline_notes


def build_page_entry(definition: dict[str, object], note_path: Path) -> NoteEntry:
    metadata, _body, _has_metadata = split_frontmatter(read_text(note_path))
    date_value = parse_datetime(metadata.get("date"))

    return {
        "title": definition["title"],
        "note_root": to_web_dir(note_path.parent),
        "note_src": to_web_path(note_path),
        "date": datetime_to_json(date_value),
    }


def build_route(note_src: str) -> str:
    path = note_src.removeprefix("./_posts/").strip("/")
    parts = path.split("/")
    if len(parts) < 2:
        return "#/overview"
    category = parts[0]
    if category == "LEA":
        slug = Path(parts[-1]).stem.lower()
    elif len(parts) == 2:
        slug = Path(parts[1]).stem
    else:
        slug = parts[1]
    return f"#/{category}/{slug}"


def build_timeline_markdown(timeline_notes: list[NoteEntry]) -> str:
    now = datetime.now().astimezone().isoformat(timespec="seconds")

    lines = [
        "---",
        "title: Timeline",
        f"date: {now}",
        f"lastmod: {now}",
        "---",
        "",
        "# Timeline",
        "",
        '<p class="timeline-page-intro">按时间顺序整理站内文章，方便快速回看近期写了什么、补了什么、记录了什么。</p>',
        "",
        '<div class="timeline-simple-list">',
    ]

    for note in sorted(timeline_notes, key=note_sort_key, reverse=True):
        display_date = str(note["date"])[:10].replace("-", ".")
        title = html.escape(str(note.get("title") or "Untitled"))
        route = build_route(str(note.get("note_src") or ""))

        lines.extend(
            [
                f'  <a class="timeline-simple-item" href="{html.escape(route)}">',
                f'    <span class="timeline-simple-date">{display_date}</span>',
                f'    <strong class="timeline-simple-title">{title}</strong>',
                '  </a>',
            ]
        )

    lines.extend(["</div>", ""])
    return "\n".join(lines)


def write_timeline(timeline_notes: list[NoteEntry]) -> None:
    TIMELINE_PATH.write_text(build_timeline_markdown(timeline_notes), encoding="utf-8")


def build_pages() -> list[dict[str, object]]:
    pages = []
    for definition in PAGE_DEFINITIONS:
        note_path = LEA_DIR / str(definition["filename"])
        if not note_path.exists():
            continue
        pages.append(build_page_entry(definition, note_path))
    return pages


def build_navigation() -> dict[str, object]:
    notes_index, timeline_notes = build_notes_index()
    write_timeline(timeline_notes)
    pages = build_pages()
    return {
        "pages": pages,
        "notes": notes_index,
    }


def clean_pycache() -> None:
    cache_dir = ROOT / "__pycache__"
    if not cache_dir.exists():
        return

    resolved_root = ROOT.resolve()
    resolved_cache = cache_dir.resolve()
    resolved_cache.relative_to(resolved_root)
    if resolved_cache.name == "__pycache__":
        shutil.rmtree(resolved_cache)


def main() -> None:
    navigation = build_navigation()
    NAV_PATH.write_text(
        json.dumps(navigation, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )
    clean_pycache()


if __name__ == "__main__":
    main()

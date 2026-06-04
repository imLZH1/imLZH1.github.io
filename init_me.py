import argparse
import re
import shutil
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
POSTS_DIR = ROOT / "_posts"
HOME_PATH = POSTS_DIR / "LEA" / "index.md"
KEY_STORE_GLOB = "*_art_key.json"
LEGACY_KEY_STORE_PATH = ROOT / "art_key.json"

DEFAULT_DESCRIPTION = "一个基于 Markdown 的静态个人博客，用于记录文章、笔记、项目和日常想法。"
DEFAULT_KEYWORDS = "Blog, Markdown, Notes, Static Site, Personal Website"


@dataclass
class SiteConfig:
    user_id: str
    site_title: str
    site_url: str
    github_url: str
    description: str
    keywords: str


def html_text(value: str) -> str:
    return (
        value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def html_attr(value: str) -> str:
    return html_text(value).replace('"', "&quot;")


def js_template_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")


def replace_pattern(text: str, pattern: str, replacement: str, flags: int = 0) -> tuple[str, bool]:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    return updated, count > 0 and updated != text


def update_file(path: Path, updater, config: SiteConfig) -> None:
    if not path.exists():
        print(f"skip missing: {path.relative_to(ROOT).as_posix()}")
        return

    original = path.read_text(encoding="utf-8")
    updated, changes = updater(original, config)
    relative = path.relative_to(ROOT).as_posix()

    if not changes:
        print(f"unchanged: {relative}")
        return

    path.write_text(updated, encoding="utf-8")
    print(f"updated: {relative}")
    for change in changes:
        print(f"  - {change}")


def update_index_html(text: str, config: SiteConfig) -> tuple[str, list[str]]:
    changes: list[str] = []
    user_text = html_text(config.user_id)
    user_attr = html_attr(config.user_id)
    site_title_text = html_text(config.site_title)
    site_title_attr = html_attr(config.site_title)
    site_url = html_attr(config.site_url)
    description = html_attr(config.description)
    keywords = html_attr(config.keywords)

    replacements = [
        (r"<title>.*?</title>", f"<title>{site_title_text}</title>", "page title"),
        (r'(<meta name="description" content=").*?(">)', rf"\g<1>{description}\g<2>", "description"),
        (r'(<meta name="keywords" content=").*?(">)', rf"\g<1>{keywords}\g<2>", "keywords"),
        (r'(<meta name="author" content=").*?(">)', rf"\g<1>{user_attr}\g<2>", "author"),
        (r'(<meta property="og:title" content=").*?(">)', rf"\g<1>{site_title_attr}\g<2>", "og:title"),
        (r'(<meta property="og:description" content=").*?(">)', rf"\g<1>{description}\g<2>", "og:description"),
        (r'(<meta property="og:url" content=").*?(">)', rf"\g<1>{site_url}\g<2>", "og:url"),
        (r'(<div class="startup-whisper">\s*<span>).*?(</span>)', rf"\g<1>{site_title_text}\g<2>", "startup title"),
        (r'(<img class="site-avatar"[^>]* alt=").*?(">)', rf"\g<1>{user_attr}\g<2>", "avatar alt"),
        (r'(<div class="site-title">).*?(</div>)', rf"\g<1>{user_text}\g<2>", "sidebar title"),
    ]

    updated = text
    for pattern, replacement, label in replacements:
        updated, changed = replace_pattern(updated, pattern, replacement, flags=re.DOTALL)
        if changed:
            changes.append(label)

    return updated, changes


def update_app_js(text: str, config: SiteConfig) -> tuple[str, list[str]]:
    site_title = js_template_value(config.site_title)
    updated, changed = replace_pattern(
        text,
        r"document\.title = `\$\{entry\.title\} \| .*?`;",
        f"document.title = `${{entry.title}} | {site_title}`;",
    )
    return updated, ["document title suffix"] if changed else []


def remove_post_path(path: Path) -> None:
    resolved_root = POSTS_DIR.resolve()
    resolved_path = path.resolve()
    resolved_path.relative_to(resolved_root)

    relative = path.relative_to(ROOT).as_posix()
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    print(f"removed: {relative}")


def clean_posts() -> None:
    POSTS_DIR.mkdir(parents=True, exist_ok=True)
    HOME_PATH.parent.mkdir(parents=True, exist_ok=True)

    for entry in sorted(POSTS_DIR.iterdir(), key=lambda path: path.name.lower()):
        if entry == HOME_PATH.parent:
            for child in sorted(entry.iterdir(), key=lambda path: path.name.lower()):
                if child == HOME_PATH:
                    continue
                remove_post_path(child)
            continue
        remove_post_path(entry)


def build_index_md(config: SiteConfig) -> str:
    title = html_text(config.site_title)
    user = html_text(config.user_id)
    github_url = html_attr(config.github_url)

    return f"""---
title: Overview
---

<h1 class="home-page-title">{title}</h1>

<div class="home-shell">
<section class="home-hero">
<div class="home-hero-copy">
<p class="home-eyebrow">Welcome</p>
<div class="home-hero-title">Notes and Writing</div>
<p class="home-hero-lead">这里是 {user} 的个人博客，用来整理文章、笔记、项目和日常想法。</p>
</div>
</section>

<section class="home-contact">
<span class="home-contact-item"><strong>Author</strong>{user}</span>
<span class="home-contact-item"><strong>About</strong>记录、整理、分享</span>
<a class="home-contact-item" href="{github_url}">GitHub</a>
</section>

<footer class="home-footer">
<div class="home-footer-copy">
<span class="home-footer-kicker">Start here</span>
<p class="home-footer-title">写下正在发生的事。</p>
</div>
<nav class="home-footer-links" aria-label="Footer links">
<a href="#/timeline">Timeline</a>
<a href="{github_url}">GitHub</a>
</nav>
<div class="home-footer-meta">
<span>© {user}</span>
<span>Powered by Markdown</span>
</div>
</footer>
</div>
"""


def write_default_home(config: SiteConfig) -> None:
    HOME_PATH.parent.mkdir(parents=True, exist_ok=True)
    HOME_PATH.write_text(build_index_md(config), encoding="utf-8")
    print(f"created default: {HOME_PATH.relative_to(ROOT).as_posix()}")


def clean_keys() -> None:
    paths = sorted(ROOT.glob(KEY_STORE_GLOB), key=lambda path: path.name.lower())
    if LEGACY_KEY_STORE_PATH.exists():
        paths.append(LEGACY_KEY_STORE_PATH)

    if not paths:
        print(f"unchanged: {KEY_STORE_GLOB}")
        return

    for path in paths:
        path.unlink()
        print(f"removed: {path.relative_to(ROOT).as_posix()}")


def rebuild_navigation() -> None:
    import main_update as nav_builder

    nav_builder.main()
    print("regenerated: nav.json")
    print("regenerated: _posts/LEA/Timeline.md")


def build_config(user_id: str, site_title: str) -> SiteConfig:
    return SiteConfig(
        user_id=user_id,
        site_title=site_title,
        site_url=f"https://{user_id}.github.io",
        github_url=f"https://github.com/{user_id}",
        description=DEFAULT_DESCRIPTION,
        keywords=DEFAULT_KEYWORDS,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize this blog as a fresh site.")
    parser.add_argument("user_id", help="Owner id used for author, GitHub URL, and GitHub Pages URL")
    parser.add_argument("site_title", help='Site title shown in the browser and UI, for example "My Blog"')
    parser.add_argument(
        "--init",
        action="store_true",
        help="Also clean posts, write default _posts/LEA/index.md, remove *_art_key.json, and rebuild nav",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = build_config(args.user_id, args.site_title)

    update_file(ROOT / "index.html", update_index_html, config)
    update_file(ROOT / "app.js", update_app_js, config)

    if args.init:
        clean_posts()
        write_default_home(config)
        clean_keys()
        rebuild_navigation()

    print("")
    print("Initialized." if args.init else "Updated site identity.")
    print("Next steps:")
    if args.init:
        print("  1. Edit _posts/LEA/index.md to customize the default homepage.")
        print("  2. Replace imgs/tx.png and background images if needed.")
        print("  3. Edit copywriting.json for sidebar random text.")
        print("  4. Add posts under _posts/<category>/ and run python main_update.py.")
    else:
        print("  1. Edit _posts/LEA/index.md manually if homepage text should change.")
        print("  2. Run python main_update.py after changing posts or pages.")


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import mimetypes
import re
import secrets
import string
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parent
POSTS_DIR = ROOT / "_posts"
KEY_STORE_SUFFIX = "_art_key.json"
KEY_STORE_GLOB = f"*{KEY_STORE_SUFFIX}"
KEY_STORE_RANDOM_CHARS = 32

ALG = "AES-256-GCM"
VERSION = 1
BUNDLE_KIND = "markleafnote.article.v2"
KEY_BYTES = 32
IV_BYTES = 12
TAG_BYTES = 16
LOCAL_RESOURCE_PATTERN = re.compile(
    r"""!\[[^\]]*]\(\s*([^)\s]+)(?:\s+['"][^)]*['"])?\s*\)|"""
    r"""\[[^\]]+]\(\s*([^)\s]+)(?:\s+['"][^)]*['"])?\s*\)|"""
    r"""(?:src|href)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


@dataclass
class Article:
    path: Path
    relative_path: str
    header_lines: list[str]
    body: str
    metadata: dict[str, str]
    newline: str


@dataclass
class KeyStore:
    path: Path | None
    data: dict[str, object]


def b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def normalize_yaml_value(value: str | None) -> str:
    if value is None:
        return ""
    return value.strip().strip('"').strip("'").lower()


def detect_newline(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def parse_header(lines: list[str]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip().lower()] = value.strip().strip('"').strip("'")
    return metadata


def split_article(path: Path) -> Article | None:
    content = path.read_text(encoding="utf-8")
    text = content.lstrip("\ufeff\r\n")
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return None

    end_index = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end_index = index
            break

    if end_index is None:
        return None

    header_lines = [line.rstrip("\r\n") for line in lines[1:end_index]]
    body = "".join(lines[end_index + 1 :])
    relative_path = path.relative_to(ROOT).as_posix()
    return Article(
        path=path,
        relative_path=relative_path,
        header_lines=header_lines,
        body=body,
        metadata=parse_header(header_lines),
        newline=detect_newline(content),
    )


def compose_article(article: Article, body: str) -> str:
    newline = article.newline
    header = newline.join(article.header_lines)
    return f"---{newline}{header}{newline}---{newline}{body}"


def set_encrypt_value(article: Article, value: str) -> None:
    for index, line in enumerate(article.header_lines):
        if ":" not in line:
            continue
        key, _old_value = line.split(":", 1)
        if key.strip().lower() == "encrypt":
            indent = line[: len(line) - len(line.lstrip())]
            article.header_lines[index] = f"{indent}encrypt: {value}"
            article.metadata["encrypt"] = value
            return

    article.header_lines.append(f"encrypt: {value}")
    article.metadata["encrypt"] = value


def article_id(relative_path: str) -> str:
    digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()
    return f"art_{digest[:20]}"


def article_title(article: Article) -> str:
    return article.metadata.get("title") or Path(article.relative_path).stem


def looks_encrypted(body: str) -> bool:
    try:
        payload = json.loads(body.strip())
    except json.JSONDecodeError:
        return False
    return all(key in payload for key in ("id", "iv", "tag", "data"))


def is_local_resource_url(url: str) -> bool:
    value = url.strip()
    if not value or value.startswith(("#", "/", "//")):
        return False

    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        return False

    lowered = value.lower()
    return not lowered.startswith(("data:", "mailto:", "tel:", "javascript:"))


def find_local_resource_urls(markdown: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in LOCAL_RESOURCE_PATTERN.finditer(markdown):
        url = next((group for group in match.groups() if group), "").strip()
        if not is_local_resource_url(url) or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def resolve_resource_path(article: Article, url: str) -> Path | None:
    parsed = urlsplit(url.strip())
    if not parsed.path:
        return None

    article_dir = article.path.parent.resolve()
    candidate = (article.path.parent / unquote(parsed.path)).resolve()
    try:
        candidate.relative_to(article_dir)
    except ValueError:
        print(f"skip resource outside article dir: {url}")
        return None

    if not candidate.is_file():
        print(f"skip missing resource: {article.relative_path} -> {url}")
        return None
    return candidate


def companion_asset_paths(article: Article) -> list[Path]:
    assets_dir = article.path.parent / "assets"
    if not assets_dir.is_dir():
        return []

    sibling_markdown = [path for path in article.path.parent.glob("*.md") if path.is_file()]
    if len(sibling_markdown) != 1 or sibling_markdown[0] != article.path:
        return []

    return sorted(path.resolve() for path in assets_dir.rglob("*") if path.is_file())


def collect_local_resources(article: Article) -> list[dict[str, str]]:
    resources: list[dict[str, str]] = []
    seen_paths: set[Path] = set()
    for url in find_local_resource_urls(article.body):
        path = resolve_resource_path(article, url)
        if path is None or path in seen_paths:
            continue

        seen_paths.add(path)
        mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        resources.append(
            {
                "url": url,
                "path": path.relative_to(article.path.parent).as_posix(),
                "root_path": path.relative_to(ROOT).as_posix(),
                "mime": mime_type,
                "data": b64encode(path.read_bytes()),
            }
        )

    for path in companion_asset_paths(article):
        if path in seen_paths:
            continue

        seen_paths.add(path)
        relative_path = path.relative_to(article.path.parent).as_posix()
        mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        resources.append(
            {
                "url": relative_path,
                "path": relative_path,
                "root_path": path.relative_to(ROOT).as_posix(),
                "mime": mime_type,
                "data": b64encode(path.read_bytes()),
            }
        )
    return resources


def pack_article_body(article: Article, assets: list[dict[str, str]]) -> str:
    if not assets:
        return article.body

    return json.dumps(
        {
            "kind": BUNDLE_KIND,
            "markdown": article.body,
            "assets": assets,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def unpack_article_body(plaintext: str) -> tuple[str, list[dict[str, str]]]:
    try:
        bundle = json.loads(plaintext)
    except json.JSONDecodeError:
        return plaintext, []

    if not isinstance(bundle, dict) or bundle.get("kind") != BUNDLE_KIND:
        return plaintext, []

    markdown = bundle.get("markdown")
    assets = bundle.get("assets")
    if not isinstance(markdown, str) or not isinstance(assets, list):
        return plaintext, []

    valid_assets = [asset for asset in assets if isinstance(asset, dict)]
    return markdown, valid_assets


def cleanup_empty_dirs(start: Path, stop: Path) -> None:
    current = start.resolve()
    stop = stop.resolve()
    while current != stop:
        try:
            current.relative_to(stop)
        except ValueError:
            return
        try:
            current.rmdir()
        except OSError:
            return
        current = current.parent


def remove_public_resources(article: Article, assets: list[dict[str, str]]) -> None:
    article_dir = article.path.parent.resolve()
    for asset in assets:
        relative_path = asset.get("path")
        if not isinstance(relative_path, str) or not relative_path:
            continue

        path = (article.path.parent / relative_path).resolve()
        try:
            path.relative_to(article_dir)
        except ValueError:
            continue

        if path.exists() and path.is_file():
            path.unlink()
            print(f"removed resource: {path.relative_to(ROOT).as_posix()}")
            cleanup_empty_dirs(path.parent, article.path.parent)


def restore_local_resources(article: Article, assets: list[dict[str, str]]) -> int:
    article_dir = article.path.parent.resolve()
    restored = 0
    for asset in assets:
        relative_path = asset.get("path")
        encoded = asset.get("data")
        if not isinstance(relative_path, str) or not isinstance(encoded, str):
            continue

        path = (article.path.parent / relative_path).resolve()
        try:
            path.relative_to(article_dir)
        except ValueError:
            print(f"skip unsafe restored resource path: {relative_path}")
            continue

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b64decode(encoded))
        print(f"restored resource: {path.relative_to(ROOT).as_posix()}")
        restored += 1
    return restored


def random_key_store_path() -> Path:
    alphabet = string.ascii_letters + string.digits
    for _attempt in range(100):
        prefix = "".join(secrets.choice(alphabet) for _ in range(KEY_STORE_RANDOM_CHARS))
        path = ROOT / f"{prefix}{KEY_STORE_SUFFIX}"
        if not path.exists():
            return path
    raise RuntimeError("failed to generate a unique key store filename")


def find_key_store_path(create: bool) -> Path | None:
    paths = sorted(ROOT.glob(KEY_STORE_GLOB), key=lambda path: path.name.lower())
    if len(paths) > 1:
        names = ", ".join(path.name for path in paths)
        raise SystemExit(f"multiple key stores found: {names}\nKeep exactly one {KEY_STORE_GLOB} file in project root.")
    if paths:
        return paths[0]
    if create:
        return random_key_store_path()
    return None


def key_store_name(store: KeyStore) -> str:
    return store.path.name if store.path else KEY_STORE_GLOB


def read_key_store(create: bool) -> KeyStore:
    path = find_key_store_path(create=create)
    if path is None or not path.exists():
        return KeyStore(path=path, data={"version": VERSION, "articles": {}})

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    if not isinstance(data.get("articles"), dict):
        data["articles"] = {}
    data["version"] = VERSION
    return KeyStore(path=path, data=data)


def write_text_atomic(path: Path, content: str) -> None:
    temp_path = path.with_name(f"{path.name}.tmp")
    temp_path.write_text(content, encoding="utf-8")
    temp_path.replace(path)


def write_key_store(store: KeyStore) -> None:
    if store.path is None:
        store.path = random_key_store_path()
    content = json.dumps(store.data, indent=2, ensure_ascii=False) + "\n"
    write_text_atomic(store.path, content)


def remove_empty_key_store(store: KeyStore) -> None:
    if store.path and not key_store_articles(store) and store.path.exists():
        store.path.unlink()
        print(f"removed empty key store: {store.path.name}")


def key_store_articles(store: KeyStore) -> dict[str, object]:
    articles = store.data.get("articles")
    if not isinstance(articles, dict):
        raise ValueError(f"{key_store_name(store)} articles field must be a JSON object")
    return articles


def print_key_store_articles(store: KeyStore) -> None:
    articles = key_store_articles(store)
    if not articles:
        print(f"No encrypted article keys found in {key_store_name(store)}.")
        return

    print(f"Encrypted articles in {key_store_name(store)}:")
    for art_id in sorted(articles):
        info = articles[art_id]
        if not isinstance(info, dict):
            continue
        title = str(info.get("title") or "Untitled")
        path = str(info.get("path") or "")
        encrypted_at = str(info.get("encrypted_at") or "")
        suffix = f" | {encrypted_at}" if encrypted_at else ""
        print(f"  {art_id} | {title} | {path}{suffix}")
    print("  all | decrypt every listed article")


def scan_articles() -> list[Article]:
    if not POSTS_DIR.exists():
        return []

    articles: list[Article] = []
    for path in sorted(POSTS_DIR.rglob("*.md")):
        article = split_article(path)
        if article:
            articles.append(article)
    return articles


def encrypt_article(article: Article, store: KeyStore) -> bool:
    encrypt_value = normalize_yaml_value(article.metadata.get("encrypt"))
    if encrypt_value != "true":
        return False
    if looks_encrypted(article.body):
        print(f"skip already-encrypted body: {article.relative_path}")
        return False

    assets = collect_local_resources(article)
    plaintext = pack_article_body(article, assets)

    key = secrets.token_bytes(KEY_BYTES)
    iv = secrets.token_bytes(IV_BYTES)
    encrypted = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    ciphertext, tag = encrypted[:-TAG_BYTES], encrypted[-TAG_BYTES:]
    art_id = article_id(article.relative_path)

    payload = {
        "v": VERSION,
        "id": art_id,
        "alg": ALG,
        "iv": b64encode(iv),
        "tag": b64encode(tag),
        "data": b64encode(ciphertext),
    }

    articles = store.data.setdefault("articles", {})
    if not isinstance(articles, dict):
        raise ValueError(f"{key_store_name(store)} articles field must be a JSON object")

    articles[art_id] = {
        "path": article.relative_path,
        "title": article_title(article),
        "alg": ALG,
        "key": b64encode(key),
        "iv": payload["iv"],
        "tag": payload["tag"],
        "assets": len(assets),
        "encrypted_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }

    set_encrypt_value(article, "ok")
    encrypted_body = article.newline + json.dumps(payload, indent=2, ensure_ascii=False) + article.newline
    write_text_atomic(article.path, compose_article(article, encrypted_body))
    remove_public_resources(article, assets)
    print(f"encrypted {art_id}: {article.relative_path}")
    return True


def parse_payload(article: Article) -> dict[str, object] | None:
    try:
        payload = json.loads(article.body.strip())
    except json.JSONDecodeError:
        print(f"skip invalid encrypted JSON: {article.relative_path}")
        return None

    required_keys = {"id", "alg", "iv", "tag", "data"}
    if not required_keys.issubset(payload):
        print(f"skip incomplete encrypted JSON: {article.relative_path}")
        return None
    if payload.get("alg") != ALG:
        print(f"skip unsupported algorithm: {article.relative_path}")
        return None
    return payload


def decrypt_article(article: Article, store: KeyStore, target: str) -> bool:
    encrypt_value = normalize_yaml_value(article.metadata.get("encrypt"))
    if encrypt_value != "ok":
        return False

    payload = parse_payload(article)
    if not payload:
        return False

    art_id = str(payload["id"])
    if target != "all" and target != art_id:
        return False

    articles = key_store_articles(store)
    key_info = articles.get(art_id)
    if not isinstance(key_info, dict):
        print(f"missing key for {art_id}: {article.relative_path}")
        return False

    try:
        key = b64decode(str(key_info["key"]))
        iv = b64decode(str(payload["iv"]))
        tag = b64decode(str(payload["tag"]))
        ciphertext = b64decode(str(payload["data"]))
        plaintext = AESGCM(key).decrypt(iv, ciphertext + tag, None).decode("utf-8")
    except (KeyError, ValueError, InvalidTag) as error:
        print(f"decrypt failed for {art_id}: {error.__class__.__name__}")
        return False

    markdown, assets = unpack_article_body(plaintext)
    set_encrypt_value(article, "true")
    write_text_atomic(article.path, compose_article(article, markdown))
    restored = restore_local_resources(article, assets)
    articles.pop(art_id, None)
    suffix = f" ({restored} resources)" if restored else ""
    print(f"decrypted {art_id}: {article.relative_path}{suffix}")
    return True


def encrypt_all() -> None:
    store = read_key_store(create=True)
    count = 0
    for article in scan_articles():
        if encrypt_article(article, store):
            count += 1
    if count:
        write_key_store(store)
        print(f"key store: {key_store_name(store)}")
    print(f"encrypted articles: {count}")


def decrypt_selected(target: str | None) -> None:
    store = read_key_store(create=False)
    if target is None:
        print_key_store_articles(store)
        try:
            target = input("Article id or all: ").strip()
        except EOFError:
            raise SystemExit("missing decrypt target") from None
    if not target:
        raise SystemExit("missing decrypt target")

    count = 0
    for article in scan_articles():
        if decrypt_article(article, store, target):
            count += 1

    if count:
        if key_store_articles(store):
            write_key_store(store)
        else:
            remove_empty_key_store(store)
    print(f"decrypted articles: {count}")


def rebuild_navigation() -> None:
    subprocess.run(
        [sys.executable, "-B", str(ROOT / "main_update.py")],
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypt or decrypt blog articles.")
    parser.add_argument("mode", choices=("enc", "dec"), help="enc encrypts, dec decrypts")
    parser.add_argument("target", nargs="?", help="decrypt target article id, or all")
    args = parser.parse_args()

    if args.mode == "enc":
        encrypt_all()
        rebuild_navigation()
    elif args.mode == "dec":
        decrypt_selected(args.target)


if __name__ == "__main__":
    main()

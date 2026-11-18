"""Check every local href/src and fragment in a generated ExDoc site."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import sys

# ExDoc references docs_config.js from every page; HexDocs serves it per package (the version
# selector), so a local build never contains it. It is the only link allowed to be absent.
HOSTED_BY_HEXDOCS = {"docs_config.js"}


class Page(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.links = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "a" and "name" in attrs:
            self.ids.add(attrs["name"])
        for key in ("href", "src"):
            if key in attrs:
                self.links.append(attrs[key])


def check(root):
    pages = {p.resolve(): Page(p.read_text()) for p in root.rglob("*.html")}
    if not pages:
        raise ValueError("rendered documentation contains no HTML")
    errors = []
    for path, page in pages.items():
        for link in page.links:
            parts = urlsplit(link)
            if parts.scheme or parts.netloc:
                continue
            if parts.path in HOSTED_BY_HEXDOCS and not parts.fragment:
                continue
            target = (path.parent / unquote(parts.path)).resolve() if parts.path else path
            if target.is_dir():
                target /= "index.html"
            if not target.is_file():
                errors.append(f"{path.relative_to(root)}: missing {link}")
            elif parts.fragment and target in pages:
                if unquote(parts.fragment) not in pages[target].ids:
                    errors.append(f"{path.relative_to(root)}: missing anchor {link}")
    if errors:
        raise ValueError("\n".join(errors))
    print(f"Checked local links and anchors in {len(pages)} rendered pages")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 scripts/check_doc_links.py doc")
    check(Path(sys.argv[1]).resolve())

"""Turn the static build's index.html into the HTML fragment the Claude Artifact tool expects.

The Artifact host wraps the page in its own document skeleton, so the fragment must not contain <html>, <head> or
<body> tags; it keeps the <title>, the stylesheet links, the root element and the module script, all with relative
paths (`assets/...`). Usage: python scripts/make_artifact_html.py web/dist-static web/dist-static/artifact.html
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    dist = Path(argv[1] if len(argv) > 1 else "web/dist-static")
    out = Path(argv[2] if len(argv) > 2 else dist / "artifact.html")
    html = (dist / "index.html").read_text(encoding="utf-8")
    head = re.search(r"<head>(.*?)</head>", html, re.S | re.I)
    body = re.search(r"<body[^>]*>(.*?)</body>", html, re.S | re.I)
    if not head or not body:
        print("index.html has no head/body", file=sys.stderr)
        return 1
    head_html, body_html = head.group(1), body.group(1)
    keep = []
    for tag in re.findall(r"<(?:title|link|script|style)\b[^>]*>(?:.*?</(?:title|script|style)>)?", head_html, re.S | re.I):
        low = tag.lower()
        if low.startswith("<link") and "stylesheet" not in low and "modulepreload" not in low:
            continue  # favicons etc. are not needed inside the artifact
        keep.append(tag.strip())
    fragment = "\n".join(keep) + "\n" + body_html.strip() + "\n"
    fragment = fragment.replace('"./', '"').replace("'./", "'")  # relative without the leading ./
    fragment = fragment.replace("<title>", "<title>", 1)
    out.write_text(fragment, encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

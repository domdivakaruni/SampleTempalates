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
    keep: list[str] = []
    # One pattern per tag kind: void tags (<link>) must not swallow the elements that follow them.
    tag_re = re.compile(
        r"<title\b[^>]*>.*?</title>|<style\b[^>]*>.*?</style>|<script\b[^>]*>.*?</script>|<link\b[^>]*>",
        re.S | re.I,
    )
    for tag in tag_re.findall(head_html):
        low = tag.lower()
        if low.startswith("<link") and "stylesheet" not in low and "modulepreload" not in low:
            continue  # favicons etc. are not needed inside the artifact
        keep.append(tag.strip())
    if not any(t.lower().startswith("<title") for t in keep):
        keep.insert(0, "<title>Throughline</title>")
    fragment = "\n".join(keep) + "\n" + body_html.strip() + "\n"
    fragment = fragment.replace('"./', '"').replace("'./", "'")  # relative without the leading ./
    out.write_text(fragment, encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

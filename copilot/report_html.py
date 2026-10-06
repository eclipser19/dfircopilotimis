"""
Markdown report -> self-contained HTML.

Evidence text is attacker-controlled (log messages, file names, command lines), so raw
HTML in the Markdown is never passed through: markdown-it runs with html=False (tags
are shown as text) and the page carries a Content-Security-Policy that blocks scripts,
external loads and forms even if something slipped through.
"""
import html

from markdown_it import MarkdownIt

_MD = MarkdownIt("commonmark", {"html": False, "linkify": False, "typographer": False}).enable("table")

CSS = """
:root { --fg:#1f2328; --muted:#59636e; --line:#d1d9e0; --bg:#ffffff; --head:#f6f8fa; --accent:#0b5cad; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e6edf3; --muted:#9198a1; --line:#3d444d; --bg:#0d1117; --head:#151b23; --accent:#4493f8; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
       font: 14px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 1280px; margin: 0 auto; padding: 32px 24px 64px; }
h1 { font-size: 26px; margin: 0 0 8px; }
h2 { font-size: 20px; margin: 36px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
h3 { font-size: 16px; margin: 24px 0 8px; }
hr { border: 0; border-top: 1px solid var(--line); margin: 24px 0; }
a { color: var(--accent); }
.table-wrap { overflow-x: auto; margin: 12px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { border: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top;
         overflow-wrap: anywhere; }
th { background: var(--head); position: sticky; top: 0; }
tr:nth-child(even) td { background: color-mix(in srgb, var(--head) 50%, transparent); }
code { font: 12px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace; background: var(--head);
       padding: 1px 4px; border-radius: 4px; overflow-wrap: anywhere; }
pre { background: var(--head); border: 1px solid var(--line); border-radius: 6px; padding: 12px;
      white-space: pre-wrap; overflow-wrap: anywhere; }
pre code { background: none; padding: 0; }
.meta { color: var(--muted); font-size: 12px; }
@media print {
  body { font-size: 11px; } main { max-width: none; padding: 0; }
  th { position: static; } h2 { break-after: avoid; } tr, pre { break-inside: avoid; }
}
"""

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"


def to_html(markdown_text: str, title: str) -> str:
    body = _MD.render(markdown_text)
    body = body.replace("<table>", '<div class="table-wrap"><table>').replace("</table>", "</table></div>")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<title>{html.escape(title)}</title>
<style>{CSS}</style>
</head>
<body>
<main>
{body}
</main>
</body>
</html>
"""

"""Markdown report -> HTML -> PDF (WeasyPrint; needs GTK/Pango, bundled in the Docker image)."""

from html import escape

from markdown_it import MarkdownIt
from mdit_py_plugins.footnote import footnote_plugin

CSS = """
@page { size: A4; margin: 18mm 15mm; @bottom-right { content: counter(page) " / " counter(pages); font-size: 8pt; } }
body { font-family: "DejaVu Sans", Arial, sans-serif; font-size: 9.5pt; color: #1a1a1a; line-height: 1.4; }
h1 { font-size: 16pt; border-bottom: 2px solid #b3261e; padding-bottom: 4px; }
h2 { font-size: 12pt; margin-top: 18px; color: #333; }
table { border-collapse: collapse; width: 100%; margin: 6px 0; }
th, td { border: 1px solid #ccc; padding: 3px 5px; vertical-align: top; text-align: left; }
th { background: #f2f2f2; }
code { font-family: "DejaVu Sans Mono", Consolas, monospace; font-size: 8pt; word-break: break-all; }
.footnotes { font-size: 8pt; }
"""


class PdfUnavailable(RuntimeError):
    pass


def render_html(markdown: str, title: str = "Incident report") -> str:
    md = MarkdownIt("commonmark", {"html": False}).enable("table").use(footnote_plugin)
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{escape(title)}</title>"
            f"<style>{CSS}</style></head><body>{md.render(markdown)}</body></html>")


def render_pdf(markdown: str, title: str = "Incident report") -> bytes:
    try:
        from weasyprint import HTML
    except OSError as exc:  # missing GTK/Pango native libraries
        raise PdfUnavailable("WeasyPrint needs GTK; use the Docker image or export Markdown") from exc
    return HTML(string=render_html(markdown, title)).write_pdf()

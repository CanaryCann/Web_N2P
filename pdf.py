from __future__ import annotations

from pathlib import Path
from typing import Union

from weasyprint import CSS, HTML


def build_pdf(html: str, base_path: Union[str, Path]) -> bytes:
    """Render HTML into PDF bytes using WeasyPrint."""

    base_path = Path(base_path)
    document = HTML(string=html, base_url=str(base_path))
    stylesheet = CSS(filename=str(base_path / "static" / "css" / "report.css"))
    return document.write_pdf(stylesheets=[stylesheet])

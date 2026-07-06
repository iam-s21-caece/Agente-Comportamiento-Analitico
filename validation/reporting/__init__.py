"""Consolidación de resultados de campaña en reportes."""

from .report_builder import (
    CampaignReport,
    build_report,
    render_markdown,
    save_report,
)

__all__ = ["CampaignReport", "build_report", "render_markdown", "save_report"]

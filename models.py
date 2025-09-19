from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass(slots=True)
class ReportMetadata:
    """User-supplied metadata for a generated report."""

    name: str
    customer: str
    scan_date: str


@dataclass(slots=True)
class FindingRecord:
    """Normalized Nessus finding for tabular presentation and aggregation."""

    host: str
    hostname: Optional[str]
    ip_address: Optional[str]
    port: Optional[str]
    protocol: Optional[str]
    plugin_id: str
    plugin_name: str
    plugin_family: str
    severity: int
    severity_label: str
    risk_factor: str
    cvss_base: Optional[float]
    cves: List[str] = field(default_factory=list)
    description: str = ""
    solution: str = ""
    plugin_output: str = ""


@dataclass(slots=True)
class HostSeveritySummary:
    """Severity breakdown for a single host."""

    host: str
    ip_address: Optional[str]
    severity_totals: Dict[str, int]

    @property
    def total_findings(self) -> int:
        return sum(self.severity_totals.values())


@dataclass(slots=True)
class AggregatedMetrics:
    """Key metrics derived from the parsed findings."""

    severity_counts: List[tuple[str, int]]
    risk_counts: List[tuple[str, int]]
    top_hosts: List[tuple[str, int]]
    top_families: List[tuple[str, int]]
    total_findings: int
    affected_hosts: int
    average_cvss: Optional[float]


@dataclass(slots=True)
class ReportDetails:
    """Bundle of metadata, findings, and metrics for rendering."""

    metadata: ReportMetadata
    findings: List[FindingRecord]
    host_summaries: List[HostSeveritySummary]
    aggregates: AggregatedMetrics
    generated_at: datetime


@dataclass(slots=True)
class ChartCollection:
    """Data URIs for preview charts."""

    severity: str
    hosts: str
    families: str
    risks: str


@dataclass(slots=True)
class ReportBundle:
    """Container for cached report output."""

    report_id: str
    details: ReportDetails
    charts: ChartCollection
    pdf_bytes: bytes

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple

import pandas as pd
import xmltodict

from models import (
    AggregatedMetrics,
    FindingRecord,
    HostSeveritySummary,
    ReportDetails,
    ReportMetadata,
)

SEVERITY_LABELS = {
    0: "Info",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


class ParserError(Exception):
    """Base exception for parsing issues."""


class InvalidNessusFile(ParserError):
    """Raised when the Nessus file cannot be parsed."""


class EmptyReportError(ParserError):
    """Raised when the Nessus file contains no findings."""


def build_report(metadata: ReportMetadata, xml_bytes: bytes) -> ReportDetails:
    """Parse Nessus XML bytes and generate report details."""

    if not xml_bytes.strip():
        raise InvalidNessusFile("The uploaded file is empty.")

    try:
        parsed = xmltodict.parse(xml_bytes, force_list={"ReportHost", "ReportItem", "tag", "cve"})
    except Exception as exc:  # pragma: no cover - xmltodict error already descriptive
        raise InvalidNessusFile("Unable to parse Nessus XML.") from exc

    report = _extract_report(parsed)
    findings, dataframe = _build_findings(report)

    if dataframe.empty:
        raise EmptyReportError("The Nessus export does not include any findings.")

    aggregates = _aggregate_metrics(dataframe)
    host_summaries = _summarize_hosts(dataframe)

    return ReportDetails(
        metadata=metadata,
        findings=findings,
        host_summaries=host_summaries,
        aggregates=aggregates,
        generated_at=datetime.now(timezone.utc),
    )


def _extract_report(parsed: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return parsed["NessusClientData_v2"]["Report"]
    except KeyError as exc:
        raise InvalidNessusFile("The file is not a valid Nessus export.") from exc


def _build_findings(report: Dict[str, Any]) -> Tuple[List[FindingRecord], pd.DataFrame]:
    hosts = _ensure_list(report.get("ReportHost", []))
    rows: List[Dict[str, Any]] = []
    findings: List[FindingRecord] = []

    for host in hosts:
        host_name = host.get("@name") or "Unknown Host"
        properties = _extract_host_properties(host)
        display_name = properties.get("host-fqdn") or properties.get("host-name") or host_name
        ip_address = properties.get("host-ip")

        for item in _ensure_list(host.get("ReportItem", [])):
            severity = _to_int(item.get("@severity"), default=0)
            severity_label = SEVERITY_LABELS.get(severity, "Info")
            plugin_family = item.get("@pluginFamily") or "Uncategorized"
            plugin_name = item.get("@pluginName") or "Unnamed Plugin"
            plugin_id = str(item.get("@pluginID") or "0")
            risk_factor = _normalize_risk_factor(item.get("risk_factor"))
            cves = _clean_cves(item.get("cve"))
            cvss_base = _to_float(item.get("cvss3_base_score"))
            if cvss_base is None:
                cvss_base = _to_float(item.get("cvss_base_score"))

            record = FindingRecord(
                host=display_name,
                hostname=properties.get("host-name"),
                ip_address=ip_address,
                port=_extract_port(item),
                protocol=item.get("@protocol"),
                plugin_id=plugin_id,
                plugin_name=plugin_name,
                plugin_family=plugin_family,
                severity=severity,
                severity_label=severity_label,
                risk_factor=risk_factor,
                cvss_base=cvss_base,
                cves=cves,
                description=_normalize_text(item.get("description")),
                solution=_normalize_text(item.get("solution")),
                plugin_output=_normalize_text(item.get("plugin_output")),
            )
            findings.append(record)

            rows.append(
                {
                    "host": display_name,
                    "hostname": properties.get("host-name"),
                    "ip_address": ip_address,
                    "severity": severity,
                    "severity_label": severity_label,
                    "risk_factor": risk_factor,
                    "plugin_family": plugin_family,
                    "plugin_name": plugin_name,
                    "plugin_id": plugin_id,
                    "cvss_base": cvss_base,
                    "cves": ", ".join(cves) if cves else "None",
                }
            )

    findings.sort(key=lambda record: (record.severity, record.cvss_base or 0.0), reverse=True)
    dataframe = pd.DataFrame(rows)
    return findings, dataframe


def _extract_host_properties(host: Dict[str, Any]) -> Dict[str, str]:
    properties: Dict[str, str] = {}
    tags = host.get("HostProperties", {}).get("tag", [])
    for tag in _ensure_list(tags):
        name = tag.get("@name")
        value = tag.get("#text") or tag.get("@value")
        if name:
            properties[name] = value or ""
    return properties


def _extract_port(item: Dict[str, Any]) -> str | None:
    port = item.get("@port")
    if port and port != "0":
        service = item.get("@svc_name")
        return f"{port}/{service}" if service else str(port)
    return None


def _aggregate_metrics(dataframe: pd.DataFrame) -> AggregatedMetrics:
    severity_series = (
        dataframe.groupby("severity_label").size().reindex(SEVERITY_ORDER, fill_value=0)
    )

    risk_series = dataframe.groupby("risk_factor").size().sort_values(ascending=False)

    top_hosts_series = (
        dataframe.groupby("host").size().sort_values(ascending=False).head(10)
    )
    top_families_series = (
        dataframe.groupby("plugin_family").size().sort_values(ascending=False).head(10)
    )

    average_cvss = None
    if "cvss_base" in dataframe and not dataframe["cvss_base"].dropna().empty:
        average_cvss = round(float(dataframe["cvss_base"].dropna().mean()), 2)

    return AggregatedMetrics(
        severity_counts=list(severity_series.items()),
        risk_counts=list(risk_series.items()),
        top_hosts=list(top_hosts_series.items()),
        top_families=list(top_families_series.items()),
        total_findings=int(len(dataframe)),
        affected_hosts=int(dataframe["host"].nunique()),
        average_cvss=average_cvss,
    )


def _summarize_hosts(dataframe: pd.DataFrame) -> List[HostSeveritySummary]:
    pivot = (
        dataframe.pivot_table(
            index=["host", "ip_address"],
            columns="severity_label",
            values="plugin_id",
            aggfunc="count",
            fill_value=0,
        )
        .reindex(columns=SEVERITY_ORDER, fill_value=0)
        .reset_index()
    )

    summaries: List[HostSeveritySummary] = []
    for _, row in pivot.iterrows():
        severity_totals = {label: int(row[label]) for label in SEVERITY_ORDER}
        summaries.append(
            HostSeveritySummary(
                host=row["host"],
                ip_address=row.get("ip_address"),
                severity_totals=severity_totals,
            )
        )
    summaries.sort(key=lambda summary: summary.total_findings, reverse=True)
    return summaries


def _ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _clean_cves(values: Iterable[Any]) -> List[str]:
    cleaned: List[str] = []
    for value in _ensure_list(values):
        if not value:
            continue
        cleaned.append(str(value).strip())
    return cleaned


def _normalize_risk_factor(value: Any) -> str:
    if not value:
        return "None"
    if isinstance(value, str):
        value = value.replace("_", " ").strip()
        return value.capitalize()
    return str(value)


def _normalize_text(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None

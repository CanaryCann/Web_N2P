from __future__ import annotations

import logging
import uuid
from collections import OrderedDict
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import charts
import parser
import pdf
from models import ChartCollection, ReportBundle, ReportDetails, ReportMetadata

LOGGER = logging.getLogger("web_n2p")
BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Web_N2P", description="Convert Nessus exports into polished PDF reports")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

_REPORT_CACHE: OrderedDict[str, ReportBundle] = OrderedDict()
_CACHE_LIMIT = 10


@app.get("/", response_class=HTMLResponse)
async def upload_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("upload.html", {"request": request})


@app.post("/generate", response_class=HTMLResponse)
async def generate_report(
    request: Request,
    file: UploadFile = File(...),
    report_name: str = Form(...),
    customer: str = Form(...),
    scan_date: str = Form(...),
) -> HTMLResponse:
    if not file.filename or not file.filename.lower().endswith(".nessus"):
        raise HTTPException(status_code=400, detail="Please upload a valid .nessus export.")

    content = await file.read()
    metadata = ReportMetadata(
        name=report_name.strip() or "Nessus Assessment",
        customer=customer.strip() or "",
        scan_date=scan_date.strip() or "",
    )

    try:
        details = parser.build_report(metadata, content)
    except parser.EmptyReportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except parser.InvalidNessusFile as exc:
        LOGGER.exception("Failed to parse Nessus file")
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    charts_payload = ChartCollection(
        severity=charts.severity_bar_chart(details.aggregates.severity_counts),
        hosts=charts.top_hosts_chart(details.aggregates.top_hosts),
        families=charts.top_families_chart(details.aggregates.top_families),
        risks=charts.risk_factor_chart(details.aggregates.risk_counts),
    )

    report_html = templates.get_template("report.html").render(
        {"details": details, "charts": charts_payload, "severity_order": parser.SEVERITY_ORDER}
    )
    pdf_bytes = pdf.build_pdf(report_html, BASE_DIR)

    report_id = _store_bundle(details, charts_payload, pdf_bytes)

    context = {
        "request": request,
        "bundle": _REPORT_CACHE[report_id],
        "metadata": details.metadata,
        "aggregates": details.aggregates,
        "host_summaries": details.host_summaries,
        "findings": details.findings[:25],
        "severity_order": parser.SEVERITY_ORDER,
        "report_id": report_id,
    }
    return templates.TemplateResponse("result.html", context)


@app.get("/reports/{report_id}.pdf")
async def download_report(report_id: str) -> Response:
    bundle = _REPORT_CACHE.get(report_id)
    if not bundle:
        raise HTTPException(status_code=404, detail="Report not found")

    headers = {
        "Content-Disposition": f"attachment; filename=nessus-report-{report_id}.pdf"
    }
    return Response(content=bundle.pdf_bytes, media_type="application/pdf", headers=headers)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if _prefers_json(request):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    context = {
        "request": request,
        "status_code": exc.status_code,
        "message": exc.detail or "An unexpected error occurred.",
    }
    return templates.TemplateResponse("error.html", context, status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):  # pragma: no cover
    LOGGER.exception("Unhandled application error")
    if _prefers_json(request):
        return JSONResponse({"detail": "Internal server error"}, status_code=500)
    context = {
        "request": request,
        "status_code": 500,
        "message": "Something went wrong while generating the report.",
    }
    return templates.TemplateResponse("error.html", context, status_code=500)


def _prefers_json(request: Request) -> bool:
    accept_header = request.headers.get("accept", "")
    return "application/json" in accept_header and "text/html" not in accept_header


def _store_bundle(details: ReportDetails, charts_payload: ChartCollection, pdf_bytes: bytes) -> str:
    report_id = uuid.uuid4().hex
    bundle = ReportBundle(
        report_id=report_id,
        details=details,
        charts=charts_payload,
        pdf_bytes=pdf_bytes,
    )
    _REPORT_CACHE[report_id] = bundle
    while len(_REPORT_CACHE) > _CACHE_LIMIT:
        _REPORT_CACHE.popitem(last=False)
    return report_id

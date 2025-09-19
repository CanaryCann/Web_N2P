# Web_N2P

## Project Description
Web_N2P is a FastAPI-powered web application that converts Nessus `.nessus` XML exports into branded HTML dashboards and polished PDF deliverables. Upload a scan, add client metadata, and instantly receive Nessus-inspired charts, host summaries, and remediation tables that can be downloaded as a styled PDF.

## Prerequisites
- Python 3.11+
- WeasyPrint system dependencies: `libpango`, `libcairo`, `libffi`

## Installation
```bash
git clone <repo>
cd Web_N2P
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running the App
```bash
uvicorn main:app --reload
```
Then open [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Usage
1. Upload a Nessus `.nessus` file and provide report metadata.
2. Click **Generate Report** to parse the XML and build visuals.
3. Review key metrics and chart previews in the browser and download the full PDF.

## Screenshots
Place screenshots of the UI and exported PDF in `docs/` when available.

## Customization
- Adjust report styling in `static/css/report.css` to match your branding.
- Update layout or copy in Jinja templates within `templates/`.
- Extend parsing behavior in `parser.py` to support additional Nessus tags.

## Known Limitations
- Large Nessus exports may take additional time to parse and render.
- Tested with Nessus v8 and v10 XML schemas.
- PDF quality depends on available system fonts and WeasyPrint support.

## License
Add your preferred license information here.

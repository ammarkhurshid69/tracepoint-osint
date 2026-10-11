"""CSV and PDF exports."""
import csv
import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

LIMITATIONS = ("Results come from third-party public sources and may be incomplete, outdated or wrong. The score is a prototype "
               "heuristic, not a validated security rating. A missing finding does not prove an asset is safe. Use only on "
               "targets you are authorised to assess.")


def safe_cell(v):
    """Neutralise spreadsheet formula injection (=, +, -, @, tab, CR)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(inv, findings) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["investigation_id", "target", "target_type", "risk_score", "source", "title", "severity", "provenance", "detail", "observed_at"])
    for f in findings:
        w.writerow([safe_cell(x) for x in (inv["id"], inv["target"], inv["target_type"], inv["risk_score"], f["source"], f["title"],
                                           f["severity"], f["provenance"], f["detail"], f["observed_at"])])
    return out.getvalue()


def to_pdf(inv, findings) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"Investigation {inv['id']}")
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=8, leading=10, textColor=colors.HexColor("#444444"))
    P = lambda t, st=body: Paragraph(escape(str(t)).replace("\n", "<br/>"), st)
    el = [Paragraph("Investigation report", ss["Title"]),
          Table([["Target", P(inv["target"])], ["Type", inv["target_type"]], ["Report generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
                 ["Last run", inv["last_run_at"] or "never"], ["Heuristic risk", f"{inv['risk_score']}/100 ({inv['risk_label']})"]],
                colWidths=[35 * mm, 135 * mm], style=TableStyle([("FONTSIZE", (0, 0), (-1, -1), 9), ("GRID", (0, 0), (-1, -1), .3, colors.grey),
                                                                  ("VALIGN", (0, 0), (-1, -1), "TOP")])),
          Spacer(1, 6 * mm), Paragraph("Summary", ss["Heading2"]),
          P(inv["summary"] or "No summary yet."), P(f"Summary method: {inv['summary_source'] or 'n/a'}", small), Spacer(1, 4 * mm),
          Paragraph("Findings", ss["Heading2"])]
    if not findings:
        el.append(P("No findings were recorded."))
    else:
        rows = [["Source", "Severity", "Finding and evidence", "Origin"]] + [
            [P(f["source"], small), f["severity"], [P(f["title"]), P(f["detail"], small)], f["provenance"]] for f in findings]
        el.append(Table(rows, colWidths=[30 * mm, 20 * mm, 106 * mm, 14 * mm], repeatRows=1, style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e4da")), ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), .3, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")])))
    el += [Spacer(1, 6 * mm), Paragraph("Limitations", ss["Heading2"]), P(LIMITATIONS, small),
           P("Origin: live = fetched from the named external source at the time shown; system = note from this application; error = lookup failed.", small)]
    doc.build(el)
    return buf.getvalue()

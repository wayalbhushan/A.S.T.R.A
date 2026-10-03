"""
ASTRA Takedown Evidence Pack PDF Generator
Renders a structured takedown evidence pack into a clean, print-friendly
PDF document using ReportLab Platypus.
Includes case metadata, verdict summary, sample indicators, recommended actions,
and pre-drafted incident notices for abuse reporting.
"""

import io
import re
import sys
import xml.sax.saxutils
from pathlib import Path
from typing import Any, Dict, List, Optional
from reportlab import rl_config
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Table,
    TableStyle,
    Spacer,
    KeepTogether,
    PageBreak,
)
import reportlab.pdfbase.pdfdoc as pdfdoc
import structlog

# Ensure backend root is on sys.path when invoked directly
backend_root = str(Path(__file__).resolve().parent.parent.parent)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

try:
    from app.analysis.takedown import defang, build_takedown_data, TEST_SCAN_STRONG, TEST_SCAN_TROJAN
except ImportError:
    from takedown import defang, build_takedown_data, TEST_SCAN_STRONG, TEST_SCAN_TROJAN

logger = structlog.get_logger()

# ReportLab's default PDFFile header and PDFDocument ID comment contain 'http://www.reportlab.com'.
# To ensure no raw 'http://' scheme enters the PDF without rewriting bytes after document creation,
# patch these internal header and comment templates to use 'hxxp://www.reportlab.com'.
# Since 'hxxp://' is the exact same byte length as 'http://' (7 bytes), all PDF offsets and xref
# tables remain 100% byte-accurate and intact.
def _patched_pdffile_init(self, pdfVersion=pdfdoc.PDF_VERSION_DEFAULT):
    self.strings = []
    self.write = self.strings.append
    self.offset = 0
    self.add((pdfdoc.pdfdocEnc("%%PDF-%s.%s" % pdfVersion) +
        b'\n%\223\214\213\236 ReportLab Generated PDF document hxxp://www.reportlab.com\n'
    ))

pdfdoc.PDFFile.__init__ = _patched_pdffile_init


def _patched_pdfdocument_id(self):
    if self._ID:
        return self._ID
    digest = self.signature.digest()
    doc = pdfdoc.DummyDoc()
    IDs = pdfdoc.PDFText(digest, enc='raw').format(doc)
    self._ID = (b'\n[' + IDs + IDs + b']\n% ReportLab generated PDF document -- digest (hxxp://www.reportlab.com)\n')
    return self._ID

pdfdoc.PDFDocument.ID = _patched_pdfdocument_id

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 18 * mm
PRINTABLE_WIDTH = PAGE_WIDTH - 2 * MARGIN

CORROBORATION_LABELS = {
    "exfil": "Exfiltration token embedded",
    "lure": "Lure wording in app name or package",
    "other_brand_cert": "Signed by another bank's certificate",
    "repackaged": "Uses the brand's official package name",
}


def safe(x: Any) -> str:
    """Sanitizes dynamic text for ReportLab XML/HTML-like markup.
    Replaces non-latin-1 encodable characters with '?', truncates to 400 characters,
    defangs URL schemes case-insensitively without touching dots,
    and escapes XML entities (&, <, >).
    """
    if x is None:
        return ""
    s = str(x)
    s = s.encode("latin-1", "replace").decode("latin-1")
    if len(s) > 400:
        s = s[:400]

    # Defang URL schemes case-insensitively before escaping XML; do not touch dots
    s = re.sub(r'(?i)https://', 'hxxps://', s)
    s = re.sub(r'(?i)http://', 'hxxp://', s)

    return xml.sax.saxutils.escape(s)


def _draw_page_footer(canvas, doc, scan_id: str):
    """Draws consistent footer on every page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#666666"))
    short_id = safe((scan_id or "")[:8])
    footer_text = f"ASTRA | Case {short_id} | Analyst review: PENDING | Page {canvas._pageNumber}"
    canvas.drawCentredString(PAGE_WIDTH / 2.0, 10 * mm, footer_text)
    canvas.restoreState()


def build_takedown_pdf(data: dict, compress: bool = True) -> bytes:
    """Builds a print-friendly takedown evidence pack PDF in memory.
    Returns exactly what ReportLab produced without post-build byte rewriting.
    
    Args:
        data: Takedown evidence pack dictionary from build_takedown_data().
        compress: Whether to enable page stream compression.
        
    Returns:
        Raw PDF document bytes.
    """
    if not isinstance(data, dict):
        data = {}

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        pageCompression=1 if compress else 0,
    )

    case = data.get("case") or {}
    sample = data.get("sample") or {}
    verdict_info = data.get("verdict") or {}
    imp = data.get("impersonation")
    indicators = data.get("indicators") or {}
    notices = data.get("notices") or []
    actions = data.get("recommended_actions") or []
    disclaimer = data.get("disclaimer") or ""

    scan_id = str(case.get("scan_id") or "")

    # Base Styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        "TakedownTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.black,
        spaceAfter=2,
    )
    
    subtitle_style = ParagraphStyle(
        "TakedownSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#555555"),
        spaceAfter=12,
    )

    h1_style = ParagraphStyle(
        "TakedownH1",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=colors.black,
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True,
    )

    h2_style = ParagraphStyle(
        "TakedownH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=13,
        textColor=colors.black,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "TakedownBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.black,
    )

    mono_style = ParagraphStyle(
        "TakedownMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        textColor=colors.black,
    )

    story = []

    # 1. Document Title
    story.append(Paragraph("ASTRA Takedown Evidence Pack", title_style))
    story.append(Paragraph("Generated by automated static analysis. Analyst review: PENDING.", subtitle_style))
    story.append(Spacer(1, 4))

    # 2. Case Details
    story.append(Paragraph("Case Details", h1_style))
    strength = data.get("evidence_strength") or "PARTIAL"
    strength_color = "#A2191F" if strength == "STRONG" else "#B28600"
    strength_html = f'<font color="{strength_color}"><b>{safe(strength)}</b></font>'

    case_rows = [
        [Paragraph("<b>Scan ID</b>", body_style), Paragraph(safe(case.get("scan_id")), mono_style)],
        [Paragraph("<b>Generated At</b>", body_style), Paragraph(safe(case.get("generated_at")), body_style)],
        [Paragraph("<b>Engine Version</b>", body_style), Paragraph(safe(case.get("engine_version")), body_style)],
        [Paragraph("<b>Evidence Strength</b>", body_style), Paragraph(strength_html, body_style)],
    ]
    case_table = Table(case_rows, colWidths=[40 * mm, PRINTABLE_WIDTH - 40 * mm])
    case_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D0D0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(case_table)
    story.append(Spacer(1, 10))

    # 3. Verdict
    story.append(Paragraph("Verdict & Threat Assessment", h1_style))
    risk_floor = verdict_info.get("risk_floor")
    floor_note = ""
    if risk_floor is not None:
        floor_note = f"<br/><font color='#555555'>Risk score raised to {safe(risk_floor)} by the impersonation finding.</font>"

    verdict_rows = [
        [Paragraph("<b>Verdict</b>", body_style), Paragraph(f"<b>{safe(verdict_info.get('verdict'))}</b>", body_style)],
        [Paragraph("<b>Risk Score</b>", body_style), Paragraph(f"{safe(verdict_info.get('risk_score'))} / 100{floor_note}", body_style)],
        [Paragraph("<b>Confidence Level</b>", body_style), Paragraph(safe(verdict_info.get("confidence_level")), body_style)],
        [Paragraph("<b>Signals Used</b>", body_style), Paragraph(f"{safe(verdict_info.get('signals_used'))} of 4", body_style)],
        [Paragraph("<b>Summary</b>", body_style), Paragraph(safe(verdict_info.get("summary")), body_style)],
    ]
    vt_ratio = verdict_info.get("virustotal_ratio")
    vt_label = verdict_info.get("virustotal_label")
    has_non_zero_ratio = False
    if vt_ratio and isinstance(vt_ratio, str):
        parts = vt_ratio.split("/")
        if parts and parts[0].strip().isdigit() and int(parts[0].strip()) > 0:
            has_non_zero_ratio = True

    if vt_label or has_non_zero_ratio:
        if has_non_zero_ratio:
            label_part = f", label {vt_label}" if vt_label else ""
            vt_sentence = f"Third-party detections (VirusTotal, not an ASTRA finding): {vt_ratio}{label_part}."
        else:
            vt_sentence = f"Third-party detections (VirusTotal, not an ASTRA finding): label {vt_label}."
        verdict_rows.append([
            Paragraph("<b>VirusTotal</b>", body_style),
            Paragraph(safe(vt_sentence), body_style),
        ])
    verdict_table = Table(verdict_rows, colWidths=[40 * mm, PRINTABLE_WIDTH - 40 * mm])
    verdict_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D0D0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 10))

    # 4. Sample
    story.append(Paragraph("Sample Details", h1_style))
    sample_rows = [
        [Paragraph("<b>File Name</b>", body_style), Paragraph(safe(sample.get("file_name")), body_style)],
        [Paragraph("<b>Package Name</b>", body_style), Paragraph(safe(sample.get("package_name")), mono_style)],
        [Paragraph("<b>Application Label</b>", body_style), Paragraph(safe(sample.get("app_label")), body_style)],
        [Paragraph("<b>Version Name</b>", body_style), Paragraph(safe(sample.get("version_name")), body_style)],
        [Paragraph("<b>SHA-256</b>", body_style), Paragraph(safe(sample.get("sha256")), mono_style)],
        [Paragraph("<b>Signer SHA-256</b>", body_style), Paragraph(safe(sample.get("signer_sha256")), mono_style)],
        [Paragraph("<b>Signer Issuer</b>", body_style), Paragraph(safe(sample.get("signer_issuer")), body_style)],
        [Paragraph("<b>Signer Subject</b>", body_style), Paragraph(safe(sample.get("signer_subject")), body_style)],
    ]
    sample_table = Table(sample_rows, colWidths=[40 * mm, PRINTABLE_WIDTH - 40 * mm])
    sample_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D0D0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sample_table)
    story.append(Spacer(1, 10))

    # 5. Impersonation Finding (only when applicable)
    if isinstance(imp, dict) and imp.get("verdict") in ["IMPERSONATION", "UNVERIFIED_CLAIM"]:
        story.append(Paragraph("Impersonation Finding", h1_style))
        evidence = imp.get("evidence") or {}
        reasons = imp.get("reasons") or []
        corroboration = evidence.get("corroboration") or []
        corr_readable = [CORROBORATION_LABELS.get(c, c) for c in corroboration]

        reasons_html = "<br/>".join([f"&bull; {safe(r)}" for r in reasons]) if reasons else "None"
        corr_html = "<br/>".join([f"&bull; {safe(c)}" for c in corr_readable]) if corr_readable else "None"

        imp_rows = [
            [Paragraph("<b>Brand Claimed</b>", body_style), Paragraph(f"<b>{safe(imp.get('brand_name'))}</b>", body_style)],
            [Paragraph("<b>Finding Verdict</b>", body_style), Paragraph(safe(imp.get("verdict")), body_style)],
            [Paragraph("<b>Confidence</b>", body_style), Paragraph(safe(imp.get("confidence")), body_style)],
            [Paragraph("<b>Matched Keyword</b>", body_style), Paragraph(safe(evidence.get("matched_keyword")), body_style)],
            [Paragraph("<b>Evidence Reasons</b>", body_style), Paragraph(reasons_html, body_style)],
            [Paragraph("<b>Corroboration</b>", body_style), Paragraph(corr_html, body_style)],
        ]
        imp_table = Table(imp_rows, colWidths=[40 * mm, PRINTABLE_WIDTH - 40 * mm])
        imp_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D0D0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(imp_table)
        story.append(Spacer(1, 10))

    # 6. Indicators
    story.append(Paragraph("Extracted Indicators", h1_style))
    note_text = indicators.get("note") or "URLs, domains and IPs are unreviewed candidates and may include legitimate services."
    story.append(Paragraph(f"<i>{safe(note_text)}</i>", subtitle_style))

    # Helper table styler
    table_base_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E5E5")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D0D0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
    ]

    # Telegram Bots Table
    tg_bots = indicators.get("telegram_bots") or []
    if tg_bots:
        story.append(Paragraph("Telegram Bots", h2_style))
        tg_data = [[Paragraph("<b>Bot ID</b>", body_style), Paragraph("<b>Masked Token</b>", body_style)]]
        for b in tg_bots:
            tg_data.append([
                Paragraph(safe(b.get("bot_id")), mono_style),
                Paragraph(safe(b.get("token_masked")), mono_style),
            ])
        t_tg = Table(tg_data, colWidths=[50 * mm, PRINTABLE_WIDTH - 50 * mm])
        t_tg.setStyle(TableStyle(table_base_style))
        story.append(t_tg)
        story.append(Spacer(1, 6))

    # Discord Webhooks Table
    dc_webhooks = indicators.get("discord_webhooks") or []
    if dc_webhooks:
        story.append(Paragraph("Discord Webhooks", h2_style))
        dc_data = [[Paragraph("<b>Webhook ID</b>", body_style), Paragraph("<b>Masked Token</b>", body_style)]]
        for w in dc_webhooks:
            dc_data.append([
                Paragraph(safe(w.get("webhook_id")), mono_style),
                Paragraph(safe(w.get("token_masked")), mono_style),
            ])
        t_dc = Table(dc_data, colWidths=[50 * mm, PRINTABLE_WIDTH - 50 * mm])
        t_dc.setStyle(TableStyle(table_base_style))
        story.append(t_dc)
        story.append(Spacer(1, 6))

    # Firebase Projects Table
    fb_projects = indicators.get("firebase_projects") or []
    if fb_projects:
        story.append(Paragraph("Firebase Projects", h2_style))
        fb_data = [[Paragraph("<b>Project</b>", body_style), Paragraph("<b>Defanged URL</b>", body_style)]]
        for p in fb_projects:
            fb_data.append([
                Paragraph(safe(p.get("project")), body_style),
                Paragraph(safe(defang(p.get("url"))), mono_style),
            ])
        t_fb = Table(fb_data, colWidths=[50 * mm, PRINTABLE_WIDTH - 50 * mm])
        t_fb.setStyle(TableStyle(table_base_style))
        story.append(t_fb)
        story.append(Spacer(1, 6))

    # AWS Keys Table
    aws_keys = indicators.get("aws_keys_masked") or []
    if aws_keys:
        story.append(Paragraph("AWS Access Keys", h2_style))
        aws_data = [[Paragraph("<b>Masked Access Key ID</b>", body_style)]]
        for k in aws_keys:
            aws_data.append([Paragraph(safe(k), mono_style)])
        t_aws = Table(aws_data, colWidths=[PRINTABLE_WIDTH])
        t_aws.setStyle(TableStyle(table_base_style))
        story.append(t_aws)
        story.append(Spacer(1, 6))

    # Network URLs Table (first 25, defanged)
    urls = indicators.get("urls") or []
    if urls:
        story.append(Paragraph(f"Network URLs ({len(urls)} shown)", h2_style))
        url_data = [[Paragraph("<b>Defanged URL Candidate</b>", body_style)]]
        for u in urls[:25]:
            url_data.append([Paragraph(safe(defang(u)), mono_style)])
        t_urls = Table(url_data, colWidths=[PRINTABLE_WIDTH])
        t_urls.setStyle(TableStyle(table_base_style))
        story.append(t_urls)
        story.append(Spacer(1, 6))

    # Domains Table
    domains = indicators.get("domains") or []
    if domains:
        story.append(Paragraph(f"Network Domains ({len(domains)} shown)", h2_style))
        dom_data = [[Paragraph("<b>Defanged Domain Candidate</b>", body_style)]]
        for d in domains[:25]:
            dom_data.append([Paragraph(safe(defang(d)), mono_style)])
        t_dom = Table(dom_data, colWidths=[PRINTABLE_WIDTH])
        t_dom.setStyle(TableStyle(table_base_style))
        story.append(t_dom)
        story.append(Spacer(1, 6))

    # IPs Table
    ips = indicators.get("ips") or []
    if ips:
        story.append(Paragraph(f"IP Addresses ({len(ips)} shown)", h2_style))
        ip_data = [[Paragraph("<b>Defanged IP Candidate</b>", body_style)]]
        for ip in ips[:25]:
            ip_data.append([Paragraph(safe(defang(ip)), mono_style)])
        t_ips = Table(ip_data, colWidths=[PRINTABLE_WIDTH])
        t_ips.setStyle(TableStyle(table_base_style))
        story.append(t_ips)
        story.append(Spacer(1, 6))

    story.append(Spacer(1, 10))

    # 7. Recommended Actions
    if actions:
        story.append(Paragraph("Recommended Actions", h1_style))
        for i, act in enumerate(actions, 1):
            story.append(Paragraph(f"<b>{i}.</b> {safe(act)}", body_style))
            story.append(Spacer(1, 3))
        story.append(Spacer(1, 10))

    # 8. Report Texts
    if notices:
        story.append(Paragraph("Draft Abuse & Incident Reporting Notices", h1_style))
        story.append(Paragraph("Review each text before sending to relevant abuse teams.", subtitle_style))

        for n in notices:
            notice_elements = []
            lbl = safe(n.get("label") or "Notice")
            ch_raw = defang(n.get("channel") or "")
            ver_text = "" if n.get("verified") else " <font color='#8A6D00'>(contact not verified)</font>"
            subj = safe(n.get("subject") or "")

            notice_elements.append(Paragraph(f"<b>{lbl}</b>", h2_style))
            notice_elements.append(Paragraph(f"<b>Channel:</b> {safe(ch_raw)}{ver_text}", body_style))
            notice_elements.append(Spacer(1, 2))
            notice_elements.append(Paragraph(f"<b>Subject:</b> {subj}", body_style))
            notice_elements.append(Spacer(1, 4))

            # Split body on newlines, call safe() on each line, join with <br/> in Courier 8.5 pt
            body_lines = [safe(line) for line in (n.get("body") or "").splitlines()]
            body_markup = "<font face='Courier' size='8.5'>" + "<br/>".join(body_lines) + "</font>"
            
            # Wrap body in light bordered table for visual clarity
            body_table = Table([[Paragraph(body_markup, mono_style)]], colWidths=[PRINTABLE_WIDTH])
            body_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F9F9F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D8D8D8")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]))
            notice_elements.append(body_table)
            notice_elements.append(Spacer(1, 10))

            # Wrap notice in KeepTogether so short notices don't break awkwardly across pages
            story.append(KeepTogether(notice_elements))

    # 9. Disclaimer Box
    story.append(Spacer(1, 8))
    disclaimer_text = disclaimer or "Generated by automated static analysis. Not reviewed by a human. Confirm the findings before acting on or sending any part of this report."
    disc_table = Table([[Paragraph(f"<b>DISCLAIMER:</b> {safe(disclaimer_text)}", body_style)]], colWidths=[PRINTABLE_WIDTH])
    disc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F2F2F2")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#BFBFBF")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(disc_table)

    # Build document with footer callback on every page
    doc.build(
        story,
        onFirstPage=lambda c, d: _draw_page_footer(c, d, scan_id),
        onLaterPages=lambda c, d: _draw_page_footer(c, d, scan_id),
    )

    return buffer.getvalue()


if __name__ == "__main__":
    print("Running ASTRA Takedown PDF Generator Test Suite...")
    total_tests = 8
    passed_tests = 0

    # Ensure ASCII85 is disabled inside test only so uncompressed stream contains raw text
    rl_config.useA85 = 0

    # Generate test fixture from takedown.py's own strong impersonation scan
    test_pack = build_takedown_data(TEST_SCAN_STRONG)

    # a. Build with compress=False. Positive control: text must contain 'Takedown Evidence Pack'
    pdf_uncompressed = build_takedown_pdf(test_pack, compress=False)
    if b"Takedown Evidence Pack" in pdf_uncompressed:
        print("PASS: Test a - Positive control passed (uncompressed PDF contains 'Takedown Evidence Pack')")
        passed_tests += 1
    else:
        print("FAIL: Test a - positive control failed (cannot verify secret absence if text is not plain)")

    # b. Starts with b"%PDF" and has at least 2 pages
    starts_pdf = pdf_uncompressed.startswith(b"%PDF")
    page_count = len(re.findall(rb'/Type\s*/Page\b', pdf_uncompressed))
    if starts_pdf and page_count >= 2:
        print(f"PASS: Test b - PDF starts with %PDF and has {page_count} pages (>= 2)")
        passed_tests += 1
    else:
        print(f"FAIL: Test b - PDF header or page count failed (starts_pdf={starts_pdf}, pages={page_count})")

    # c. Bytes contain none of the secrets, and contain "123456789"
    secrets_to_check = [
        b"AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
        b"abcDEF_ghiJKL-mnoPQR",
        b"AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBc",
    ]
    leaked = [s for s in secrets_to_check if s in pdf_uncompressed]
    has_bot_id = b"123456789" in pdf_uncompressed
    if not leaked and has_bot_id:
        print("PASS: Test c - No secrets leaked in PDF bytes, bot ID 123456789 is present")
        passed_tests += 1
    else:
        print(f"FAIL: Test c - Secrets check failed (leaked={leaked}, has_bot_id={has_bot_id})")

    # d. Build with compress=False from a fixture with http/https/uppercase in all 6 required places
    url_a = "http://x.example/a"
    url_b = "https://y.example/b"
    url_c = "HTTP://UPPER.example/c"
    urls_combined = f"{url_a} {url_b} {url_c}"

    scan_d = {
        "id": "33333333-3333-3333-3333-333333333333",
        "file_name": "test_d.apk",
        "file_hash": "b" * 64,
        "package_name": f"com.example.{urls_combined}",
        "verdict": "MALICIOUS",
        "risk_score": 80.0,
        "threat_summary": f"Detected malware with {urls_combined}",
        "impersonation": {
            "verdict": "IMPERSONATION",
            "brand_name": "TestBank",
            "reasons": [
                f"Suspicious endpoint {urls_combined}"
            ],
            "evidence": {
                "corroboration": ["exfil"]
            }
        },
        "androguard_data": {
            "app_name": f"TestApp {urls_combined}",
            "package_name": f"com.example.{urls_combined}",
            "extracted_iocs": {
                "secrets": {
                    "firebase_urls": [
                        f"{url_a}.firebaseio.com",
                        f"{url_b}.firebaseio.com",
                        f"{url_c}.firebaseio.com",
                    ]
                },
                "network": {
                    "urls": [url_a, url_b, url_c]
                }
            }
        }
    }

    pack_d = build_takedown_data(scan_d)
    pdf_d = build_takedown_pdf(pack_d, compress=False)

    has_raw_http = b"http://" in pdf_d or b"https://" in pdf_d or b"http://" in pdf_d.lower()
    has_hxxp = b"hxxp" in pdf_d

    if not has_raw_http and has_hxxp:
        print("PASS: Test d - Fixture with raw and uppercase URL schemes defanged properly (no raw http/https, contains hxxp)")
        passed_tests += 1
    else:
        print(f"FAIL: Test d - Defanging check failed (has_raw_http={has_raw_http}, has_hxxp={has_hxxp})")

    # e. Special characters and Unicode app labels build without exception
    label_tests_ok = True
    for test_label in ["<b>EVIL</b> & <script>x</script>", "एसबीआई बैंक"]:
        try:
            custom_scan = dict(TEST_SCAN_STRONG)
            custom_andro = dict(custom_scan.get("androguard_data") or {})
            custom_andro["app_name"] = test_label
            custom_scan["androguard_data"] = custom_andro
            pack_custom = build_takedown_data(custom_scan)
            pdf_custom = build_takedown_pdf(pack_custom, compress=False)
            if not pdf_custom.startswith(b"%PDF"):
                label_tests_ok = False
        except Exception as e:
            print(f"Label test failed for '{test_label}': {e}")
            label_tests_ok = False

    if label_tests_ok:
        print("PASS: Test e - HTML injection strings and non-Latin-1 Unicode build safely without exception")
        passed_tests += 1
    else:
        print("FAIL: Test e - Dynamic character sanitization test failed")

    # f. compress=True builds successfully and is smaller than uncompressed output
    pdf_compressed = build_takedown_pdf(test_pack, compress=True)
    comp_ok = pdf_compressed.startswith(b"%PDF")
    is_smaller = len(pdf_compressed) < len(pdf_uncompressed)
    if comp_ok and is_smaller:
        print(f"PASS: Test f - Compressed PDF is valid and smaller ({len(pdf_compressed)} < {len(pdf_uncompressed)} bytes)")
        passed_tests += 1
    else:
        print(f"FAIL: Test f - Compression test failed (comp_ok={comp_ok}, is_smaller={is_smaller})")

    # g. File offsets and xref integrity check for both uncompressed and compressed outputs
    test_g_ok = True
    for comp in [False, True]:
        pdf_out = build_takedown_pdf(test_pack, compress=comp)
        stripped = pdf_out.rstrip()
        if not stripped.endswith(b"%%EOF"):
            test_g_ok = False
            print(f"FAIL: Test g - compress={comp} does not end with %%EOF")
            break
        last_startxref = stripped.rfind(b"startxref")
        if last_startxref == -1:
            test_g_ok = False
            print(f"FAIL: Test g - compress={comp} startxref not found")
            break
        offset_part = stripped[last_startxref + len(b"startxref"):].strip().split()[0]
        try:
            offset = int(offset_part)
        except ValueError:
            test_g_ok = False
            print(f"FAIL: Test g - compress={comp} invalid startxref offset: {offset_part}")
            break
        if not stripped[offset:].startswith(b"xref"):
            test_g_ok = False
            print(f"FAIL: Test g - compress={comp} bytes at offset {offset} do not start with xref")
            break

    if test_g_ok:
        print("PASS: Test g - PDF file offsets and xref tables intact (ends with %%EOF, valid startxref) for compress=False and compress=True")
        passed_tests += 1

    # h. Trojan fixture builds and uncompressed bytes contain "28/67"
    pack_trojan = build_takedown_data(TEST_SCAN_TROJAN)
    pdf_trojan = build_takedown_pdf(pack_trojan, compress=False)
    h_ok = pdf_trojan.startswith(b"%PDF") and b"28/67" in pdf_trojan
    if h_ok:
        print("PASS: Test h - Trojan fixture builds valid PDF and bytes contain '28/67'")
        passed_tests += 1
    else:
        print(f"FAIL: Test h - Trojan fixture PDF failed (starts_pdf={pdf_trojan.startswith(b'%PDF')}, has_ratio={b'28/67' in pdf_trojan})")

    print(f"\nFinal Result: {passed_tests}/{total_tests} tests passed.")

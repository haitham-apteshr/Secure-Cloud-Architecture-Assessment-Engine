"""
PDF Report Generator for WAF Assessment — CloudSecurityApp
Produces a professional, technical, board-ready report with:
  - Executive Summary
  - Risk Heat Matrix
  - Per-Pillar Technical Analysis (with gap lists and remediation roadmaps)
  - Prioritized Remediation Register (Critical → Low, with effort and success metrics)
  - Full Evidence Appendix
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.platypus.flowables import Flowable
from datetime import datetime
from typing import Dict, List
import re

# ── Colour Palette ────────────────────────────────────────────────────────────
C_NAVY       = colors.HexColor('#0f172a')
C_BLUE       = colors.HexColor('#1d4ed8')
C_BLUE_LIGHT = colors.HexColor('#dbeafe')
C_BLUE_MID   = colors.HexColor('#3b82f6')
C_SLATE      = colors.HexColor('#334155')
C_SLATE_LIGHT= colors.HexColor('#f1f5f9')
C_BORDER     = colors.HexColor('#cbd5e1')
C_CRITICAL   = colors.HexColor('#dc2626')
C_HIGH       = colors.HexColor('#ea580c')
C_MEDIUM     = colors.HexColor('#d97706')
C_LOW        = colors.HexColor('#16a34a')
C_WHITE      = colors.white

PILLAR_COLORS = {
    'Operational Excellence': colors.HexColor('#6366f1'),
    'Security':               colors.HexColor('#ef4444'),
    'Reliability':            colors.HexColor('#3b82f6'),
    'Performance Efficiency': colors.HexColor('#8b5cf6'),
    'Cost Optimization':      colors.HexColor('#10b981'),
    'Sustainability':         colors.HexColor('#f59e0b'),
}

PRIORITY_COLORS = {
    'Critical': C_CRITICAL,
    'High':     C_HIGH,
    'Medium':   C_MEDIUM,
    'Low':      C_LOW,
}

MATURITY_LABELS = {
    0: 'Unknown',
    1: 'Ad-Hoc / Initial',
    2: 'Baseline / Repeatable',
    3: 'Standardized / Defined',
    4: 'Optimized / Managed',
    5: 'Continuously Improved',
}


def _maturity_color(score: float) -> colors.Color:
    if score >= 4.0: return C_LOW
    if score >= 3.0: return colors.HexColor('#65a30d')
    if score >= 2.0: return C_MEDIUM
    if score >= 1.0: return C_HIGH
    return C_CRITICAL


def _priority_color(priority: str) -> colors.Color:
    return PRIORITY_COLORS.get(priority, C_SLATE)


def _strip_md(text: str) -> str:
    """Strip Markdown so ReportLab doesn't choke — convert bold to <b> tags."""
    if not text:
        return ''
    # Convert **bold** → <b>bold</b>
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    # Convert `code` → <font face="Courier" size="8">code</font>
    text = re.sub(r'`(.*?)`', r'<font face="Courier" size="8">\1</font>', text)
    # Drop standalone # headers (we handle them as Paragraphs)
    text = re.sub(r'^#+\s*', '', text, flags=re.MULTILINE)
    return text.strip()


class ScoreBar(Flowable):
    """A horizontal coloured bar representing a score out of 5."""
    def __init__(self, score: float, width=200, height=14):
        super().__init__()
        self.score = min(max(score, 0), 5)
        self.width = width
        self.height = height

    def draw(self):
        fill = _maturity_color(self.score)
        pct  = self.score / 5.0
        # Background track
        self.canv.setFillColor(C_BORDER)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        # Score fill
        self.canv.setFillColor(fill)
        self.canv.rect(0, 0, self.width * pct, self.height, fill=1, stroke=0)
        # Score label
        self.canv.setFillColor(C_NAVY)
        self.canv.setFont('Helvetica-Bold', 8)
        self.canv.drawRightString(self.width + 35, 3, f'{self.score:.1f}/5')


class PDFReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        add = self.styles.add

        add(ParagraphStyle('ReportTitle',    parent=self.styles['Heading1'],
            fontSize=28, textColor=C_WHITE, alignment=TA_CENTER,
            spaceAfter=6, fontName='Helvetica-Bold'))

        add(ParagraphStyle('ReportSubtitle', parent=self.styles['Normal'],
            fontSize=12, textColor=C_BLUE_LIGHT, alignment=TA_CENTER, spaceAfter=4))

        add(ParagraphStyle('SectionHeader',  parent=self.styles['Heading2'],
            fontSize=15, textColor=C_BLUE, spaceAfter=8, spaceBefore=18,
            fontName='Helvetica-Bold', borderPad=0))

        add(ParagraphStyle('SubHeader',      parent=self.styles['Heading3'],
            fontSize=11, textColor=C_NAVY, spaceAfter=4, spaceBefore=10,
            fontName='Helvetica-Bold'))

        add(ParagraphStyle('Body',           parent=self.styles['BodyText'],
            fontSize=9, textColor=C_NAVY, alignment=TA_JUSTIFY,
            spaceAfter=6, leading=14))

        add(ParagraphStyle('BodySmall',      parent=self.styles['BodyText'],
            fontSize=8, textColor=C_SLATE, spaceAfter=4, leading=12))

        add(ParagraphStyle('BulletBody',     parent=self.styles['BodyText'],
            fontSize=9, textColor=C_NAVY, leftIndent=14,
            bulletIndent=4, spaceAfter=3, leading=13))

        add(ParagraphStyle('TableHeader',    parent=self.styles['Normal'],
            fontSize=9, textColor=C_WHITE, fontName='Helvetica-Bold',
            alignment=TA_CENTER))

        add(ParagraphStyle('TableCell',      parent=self.styles['Normal'],
            fontSize=8, textColor=C_NAVY, leading=11))

        add(ParagraphStyle('TableCellSmall', parent=self.styles['Normal'],
            fontSize=7.5, textColor=C_SLATE, leading=10))

        add(ParagraphStyle('MetaLabel',      parent=self.styles['Normal'],
            fontSize=8, textColor=C_SLATE, spaceAfter=1))

        add(ParagraphStyle('MetaValue',      parent=self.styles['Normal'],
            fontSize=9, textColor=C_NAVY, spaceAfter=6, fontName='Helvetica-Bold'))

        add(ParagraphStyle('PillarName',     parent=self.styles['Normal'],
            fontSize=10, textColor=C_NAVY, fontName='Helvetica-Bold', spaceAfter=2))

        add(ParagraphStyle('RiskLabel',      parent=self.styles['Normal'],
            fontSize=8, textColor=C_WHITE, fontName='Helvetica-Bold',
            alignment=TA_CENTER))

        add(ParagraphStyle('FooterStyle',    parent=self.styles['Normal'],
            fontSize=7, textColor=C_SLATE, alignment=TA_CENTER))

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_report(self, session_data: Dict, output_path: str) -> str:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=18*mm, leftMargin=18*mm,
            topMargin=20*mm,   bottomMargin=20*mm,
            title="WAF Assessment Report — CloudSecurityApp",
        )

        story = []
        story.extend(self._cover_page(session_data))
        story.append(PageBreak())
        story.extend(self._executive_summary(session_data))
        story.append(PageBreak())
        story.extend(self._maturity_dashboard(session_data))
        story.extend(self._risk_heatmap(session_data))
        story.append(PageBreak())
        story.extend(self._pillar_analysis(session_data))
        story.append(PageBreak())
        story.extend(self._remediation_register(session_data))
        story.append(PageBreak())
        story.extend(self._evidence_appendix(session_data))

        doc.build(story, onFirstPage=self._footer, onLaterPages=self._footer)
        return output_path

    def _footer(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_SLATE)
        canvas.setFont('Helvetica', 7)
        canvas.drawString(18*mm, 10*mm,
            f"CloudSecurityApp — WAF Assessment Report   |   CONFIDENTIAL   |   {datetime.now().strftime('%Y-%m-%d')}")
        canvas.drawRightString(A4[0] - 18*mm, 10*mm, f"Page {doc.page}")
        canvas.restoreState()

    # ── Cover Page ────────────────────────────────────────────────────────────

    def _cover_page(self, data: Dict) -> List:
        els = []
        # Dark header band
        header_data = [[Paragraph('CloudSecurityApp', self.styles['ReportTitle'])],
                       [Paragraph('AWS Well-Architected Framework Assessment Report', self.styles['ReportSubtitle'])]]
        header_table = Table(header_data, colWidths=[175*mm])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_NAVY),
            ('TOPPADDING',    (0,0), (-1,-1), 22),
            ('BOTTOMPADDING', (0,0), (-1,-1), 16),
            ('LEFTPADDING',   (0,0), (-1,-1), 10),
            ('RIGHTPADDING',  (0,0), (-1,-1), 10),
        ]))
        els.append(header_table)
        els.append(Spacer(1, 10*mm))

        # Metadata grid
        meta = [
            ('Assessment Date',  datetime.now().strftime('%B %d, %Y')),
            ('Session ID',       data.get('session_id', 'N/A')[:16] + '…'),
            ('Workload Type',    data.get('workload_profile', {}).get('type', 'Not specified')),
            ('Overall Maturity', f"{data.get('average_score', 0):.1f} / 5.0"),
            ('Questions Covered', str(len(data.get('qa_log', [])))),
            ('Classification',   'CONFIDENTIAL'),
        ]
        meta_table_data = []
        for i in range(0, len(meta), 2):
            row = []
            for label, value in meta[i:i+2]:
                row.append(Paragraph(label.upper(), self.styles['MetaLabel']))
                row.append(Paragraph(value, self.styles['MetaValue']))
            if len(row) < 4:
                row.extend([Paragraph('', self.styles['MetaLabel']),
                             Paragraph('', self.styles['MetaValue'])])
            meta_table_data.append(row)

        mt = Table(meta_table_data, colWidths=[40*mm, 47*mm, 40*mm, 47*mm])
        mt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_SLATE_LIGHT),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('LEFTPADDING',   (0,0), (-1,-1), 6),
            ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
            ('LINEBELOW', (0,0), (-1,-2), 0.5, C_BORDER),
        ]))
        els.append(mt)
        els.append(Spacer(1, 8*mm))

        # Overall score prominent display
        avg = data.get('average_score', 0)
        mat = MATURITY_LABELS.get(int(round(avg)), 'Unknown')
        score_color = _maturity_color(avg)
        score_data = [[
            Paragraph(f'<font color="{score_color.hexval()}"><b>{avg:.1f}</b></font>', ParagraphStyle(
                'BigScore', parent=self.styles['Normal'],
                fontSize=52, alignment=TA_CENTER, textColor=score_color, fontName='Helvetica-Bold'
            )),
            Paragraph(
                f'<b>Overall Maturity Score</b><br/><br/>'
                f'{mat}<br/><br/>'
                f'<font size="8" color="#64748b">Scored across 6 WAF pillars based on<br/>'
                f'{len(data.get("qa_log", []))} evidence-backed interview responses.</font>',
                ParagraphStyle('ScoreDesc', parent=self.styles['Normal'],
                    fontSize=11, textColor=C_NAVY, leading=16)
            )
        ]]
        st = Table(score_data, colWidths=[55*mm, 120*mm])
        st.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BACKGROUND', (0,0), (-1,-1), C_SLATE_LIGHT),
            ('BOX', (0,0), (-1,-1), 1, score_color),
            ('TOPPADDING',    (0,0), (-1,-1), 12),
            ('BOTTOMPADDING', (0,0), (-1,-1), 12),
            ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ]))
        els.append(st)

        els.append(Spacer(1, 6*mm))
        els.append(Paragraph(
            '<i>This report is the output of an AI-driven conversational assessment against the AWS '
            'Well-Architected Framework. It contains technical risk analysis, maturity scores per pillar, '
            'and a prioritised remediation roadmap. Contents are CONFIDENTIAL.</i>',
            self.styles['BodySmall']
        ))
        return els

    # ── Executive Summary ─────────────────────────────────────────────────────

    def _executive_summary(self, data: Dict) -> List:
        els = []
        els.append(Paragraph('Executive Summary', self.styles['SectionHeader']))
        els.append(HRFlowable(width='100%', thickness=1, color=C_BLUE))
        els.append(Spacer(1, 4*mm))

        summary = data.get('executive_summary', '')
        if summary:
            # Try to split into paragraphs
            paras = [p.strip() for p in summary.split('\n\n') if p.strip()]
            for p in paras:
                els.append(Paragraph(_strip_md(p), self.styles['Body']))
        else:
            els.append(Paragraph('Executive summary not available.', self.styles['Body']))

        return els

    # ── Maturity Dashboard ────────────────────────────────────────────────────

    def _maturity_dashboard(self, data: Dict) -> List:
        els = []
        els.append(Paragraph('Maturity Dashboard — All Pillars', self.styles['SectionHeader']))
        els.append(HRFlowable(width='100%', thickness=1, color=C_BLUE))
        els.append(Spacer(1, 3*mm))

        scores = data.get('pillar_scores', [])
        if not scores:
            els.append(Paragraph('No pillar scores available.', self.styles['Body']))
            return els

        table_data = [[
            Paragraph('PILLAR', self.styles['TableHeader']),
            Paragraph('SCORE', self.styles['TableHeader']),
            Paragraph('MATURITY LEVEL', self.styles['TableHeader']),
            Paragraph('VISUAL', self.styles['TableHeader']),
            Paragraph('STATUS', self.styles['TableHeader']),
        ]]

        for ps in scores:
            pillar = ps.get('pillar', 'Unknown')
            score  = float(ps.get('score', 0))
            mat    = ps.get('maturity', MATURITY_LABELS.get(int(round(score)), 'Unknown'))
            col    = _maturity_color(score)

            if score < 2:    status, sc = 'CRITICAL GAP',   C_CRITICAL
            elif score < 3:  status, sc = 'NEEDS WORK',     C_HIGH
            elif score < 4:  status, sc = 'ADEQUATE',       C_MEDIUM
            else:            status, sc = 'STRONG',         C_LOW

            pcolor = PILLAR_COLORS.get(pillar, C_BLUE)
            table_data.append([
                Paragraph(f'<b>{pillar}</b>', self.styles['TableCell']),
                Paragraph(f'<b><font color="{col.hexval()}">{score:.1f}/5</font></b>',
                          ParagraphStyle('ScoreCell', parent=self.styles['TableCell'], alignment=TA_CENTER)),
                Paragraph(mat, self.styles['TableCellSmall']),
                ScoreBar(score, width=130, height=12),
                Paragraph(f'<b>{status}</b>',
                          ParagraphStyle('StatusCell', parent=self.styles['TableCell'],
                              textColor=sc, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            ])

        t = Table(table_data, colWidths=[52*mm, 18*mm, 38*mm, 40*mm, 25*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0),  C_NAVY),
            ('TEXTCOLOR',     (0,0), (-1,0),  C_WHITE),
            ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
            ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_WHITE, C_SLATE_LIGHT]),
            ('GRID',          (0,0), (-1,-1), 0.4, C_BORDER),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 6),
        ]))
        els.append(t)
        els.append(Spacer(1, 4*mm))

        # Legend
        legend = [
            ('■', C_CRITICAL, 'Critical Gap (< 2.0)'),
            ('■', C_HIGH,     'Needs Work (2.0–2.9)'),
            ('■', C_MEDIUM,   'Adequate (3.0–3.9)'),
            ('■', C_LOW,      'Strong (≥ 4.0)'),
        ]
        legend_parts = '    '.join(
            f'<font color="{c.hexval()}">{s}</font> {label}'
            for s, c, label in legend
        )
        els.append(Paragraph(legend_parts, ParagraphStyle(
            'Legend', parent=self.styles['BodySmall'], alignment=TA_CENTER)))
        return els

    # ── Risk Heatmap ──────────────────────────────────────────────────────────

    def _risk_heatmap(self, data: Dict) -> List:
        els = []
        els.append(Spacer(1, 6*mm))
        els.append(Paragraph('Risk Summary Matrix', self.styles['SectionHeader']))
        els.append(HRFlowable(width='100%', thickness=1, color=C_BLUE))
        els.append(Spacer(1, 3*mm))

        recs = data.get('recommendations', [])
        count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for r in recs:
            p = r.get('priority', 'Medium')
            if p in count: count[p] += 1

        # Total gaps heatmap
        cells = []
        for level in ['Critical', 'High', 'Medium', 'Low']:
            c = count[level]
            bg = _priority_color(level)
            cells.append([
                Paragraph(
                    f'<b><font size="26">{c}</font><br/><br/>{level}</b>',
                    ParagraphStyle('HeatCell', parent=self.styles['Normal'],
                        fontSize=10, textColor=C_WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER)
                )
            ])

        hm = Table([[c[0] for c in cells]], colWidths=[40*mm]*4)
        styles_list = [
            ('BACKGROUND', (0,0), (0,-1), C_CRITICAL),
            ('BACKGROUND', (1,0), (1,-1), C_HIGH),
            ('BACKGROUND', (2,0), (2,-1), C_MEDIUM),
            ('BACKGROUND', (3,0), (3,-1), C_LOW),
            ('TOPPADDING',    (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('BOX',           (0,0), (-1,-1), 0.5, C_BORDER),
            ('INNERGRID',     (0,0), (-1,-1), 0.5, C_WHITE),
            ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
        ]
        hm.setStyle(TableStyle(styles_list))
        els.append(hm)
        els.append(Spacer(1, 2*mm))
        els.append(Paragraph(
            'Total recommendations by priority across all WAF pillars.',
            self.styles['BodySmall']))
        return els

    # ── Per-Pillar Technical Analysis ─────────────────────────────────────────

    def _pillar_analysis(self, data: Dict) -> List:
        els = []
        els.append(Paragraph('Per-Pillar Technical Analysis', self.styles['SectionHeader']))
        els.append(HRFlowable(width='100%', thickness=1, color=C_BLUE))
        els.append(Spacer(1, 2*mm))

        scores_map = {ps.get('pillar'): ps for ps in data.get('pillar_scores', [])}
        qa_log     = data.get('qa_log', [])
        recs_map   = {}
        for r in data.get('recommendations', []):
            p = r.get('pillar', 'General')
            recs_map.setdefault(p, []).append(r)

        pillars = ['Operational Excellence', 'Security', 'Reliability',
                   'Performance Efficiency', 'Cost Optimization', 'Sustainability']

        for pillar in pillars:
            ps    = scores_map.get(pillar, {})
            score = float(ps.get('score', 0))
            mat   = ps.get('maturity', MATURITY_LABELS.get(int(round(score)), 'Unknown'))
            pcolor= PILLAR_COLORS.get(pillar, C_BLUE)
            mat_color = _maturity_color(score)

            # Pillar header band
            header_data = [[
                Paragraph(f'<b>{pillar}</b>',
                          ParagraphStyle('PH', parent=self.styles['Normal'],
                              fontSize=12, textColor=C_WHITE, fontName='Helvetica-Bold')),
                Paragraph(f'<b><font size="14">{score:.1f}/5</font></b><br/>'
                          f'<font size="8">{mat}</font>',
                          ParagraphStyle('PHS', parent=self.styles['Normal'],
                              fontSize=9, textColor=C_WHITE, alignment=TA_RIGHT)),
            ]]
            hdr = Table(header_data, colWidths=[130*mm, 43*mm])
            hdr.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), pcolor),
                ('TOPPADDING',    (0,0), (-1,-1), 7),
                ('BOTTOMPADDING', (0,0), (-1,-1), 7),
                ('LEFTPADDING',   (0,0), (-1,-1), 8),
                ('RIGHTPADDING',  (0,0), (-1,-1), 8),
                ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
            ]))
            els.append(KeepTogether([hdr, Spacer(1, 2*mm)]))

            # Score bar
            els.append(ScoreBar(score, width=400, height=10))
            els.append(Spacer(1, 3*mm))

            # Relevant Q&A excerpts for this pillar
            pillar_qas = [qa for qa in qa_log if _pillar_in_analysis(qa.get('analysis', ''), pillar)]
            if not pillar_qas:
                pillar_qas = qa_log[:2]  # Fallback to first 2 if no match

            # Extract gap bullets from analysis
            gaps = _extract_gaps(pillar_qas)
            if gaps:
                els.append(Paragraph('<b>Identified Gaps</b>', self.styles['SubHeader']))
                for g in gaps[:5]:
                    els.append(Paragraph(f'• {_strip_md(g)}', self.styles['BulletBody']))
                els.append(Spacer(1, 2*mm))

            # Extract recommendations from analysis
            risks = _extract_risks(pillar_qas)
            if risks:
                els.append(Paragraph('<b>Risk Analysis</b>', self.styles['SubHeader']))
                for r in risks[:3]:
                    els.append(Paragraph(f'⚠ {_strip_md(r)}', ParagraphStyle(
                        'RiskItem', parent=self.styles['BulletBody'],
                        textColor=C_HIGH, leftIndent=14)))
                els.append(Spacer(1, 2*mm))

            # Top recommendations for this pillar
            pillar_recs = recs_map.get(pillar, [])
            if not pillar_recs:
                # Try partial match
                for k, v in recs_map.items():
                    if pillar.lower() in k.lower():
                        pillar_recs = v
                        break

            if pillar_recs:
                els.append(Paragraph('<b>Key Recommendations</b>', self.styles['SubHeader']))
                for rec in pillar_recs[:3]:
                    priority = rec.get('priority', 'Medium')
                    pc       = _priority_color(priority)
                    effort   = rec.get('effort', '')
                    els.append(Paragraph(
                        f'<b>[{priority}]</b>  {rec.get("title", "")}  '
                        f'<font color="#64748b" size="8">— {effort}</font>',
                        ParagraphStyle('RecTitle', parent=self.styles['Body'],
                            textColor=pc, fontName='Helvetica-Bold')
                    ))
                    desc = rec.get('description', '')
                    if desc:
                        els.append(Paragraph(_strip_md(desc), self.styles['BodySmall']))
                    # Action items
                    for ai in rec.get('action_items', [])[:3]:
                        els.append(Paragraph(f'    → {_strip_md(ai)}', self.styles['BulletBody']))
                    els.append(Spacer(1, 1*mm))

            els.append(HRFlowable(width='100%', thickness=0.4, color=C_BORDER))
            els.append(Spacer(1, 4*mm))

        return els

    # ── Remediation Register ──────────────────────────────────────────────────

    def _remediation_register(self, data: Dict) -> List:
        els = []
        els.append(Paragraph('Prioritised Remediation Register', self.styles['SectionHeader']))
        els.append(HRFlowable(width='100%', thickness=1, color=C_BLUE))
        els.append(Spacer(1, 3*mm))
        els.append(Paragraph(
            'The following table lists all remediation actions ordered by priority. '
            'Critical items should be addressed within 7 days; High within 30 days; '
            'Medium within 90 days; Low within 180 days.',
            self.styles['Body']
        ))
        els.append(Spacer(1, 3*mm))

        recs = data.get('recommendations', [])
        if not recs:
            els.append(Paragraph('No recommendations available.', self.styles['Body']))
            return els

        # Sort: Critical → High → Medium → Low
        priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        recs_sorted = sorted(recs, key=lambda r: priority_order.get(r.get('priority', 'Low'), 4))

        table_data = [[
            Paragraph('#',          self.styles['TableHeader']),
            Paragraph('PRIORITY',   self.styles['TableHeader']),
            Paragraph('TITLE',      self.styles['TableHeader']),
            Paragraph('PILLAR',     self.styles['TableHeader']),
            Paragraph('EFFORT',     self.styles['TableHeader']),
            Paragraph('SUCCESS METRIC', self.styles['TableHeader']),
        ]]

        row_styles = []
        for i, rec in enumerate(recs_sorted, 1):
            priority = rec.get('priority', 'Medium')
            pc       = _priority_color(priority)
            effort   = rec.get('effort', '—')
            metric   = rec.get('success_metric', '—')
            pillar   = rec.get('pillar', '—')

            row = [
                Paragraph(str(i), ParagraphStyle('Num', parent=self.styles['TableCell'],
                    alignment=TA_CENTER)),
                Paragraph(f'<b>{priority}</b>', ParagraphStyle('Pri', parent=self.styles['TableCell'],
                    textColor=pc, fontName='Helvetica-Bold', alignment=TA_CENTER)),
                Paragraph(f'<b>{rec.get("title","")}</b><br/>'
                          f'<font size="7" color="#64748b">{_strip_md(rec.get("risk_if_ignored","")[:80])}…</font>',
                          self.styles['TableCell']),
                Paragraph(pillar, self.styles['TableCellSmall']),
                Paragraph(effort, ParagraphStyle('Eff', parent=self.styles['TableCellSmall'],
                    alignment=TA_CENTER)),
                Paragraph(_strip_md(str(metric)[:70]), self.styles['TableCellSmall']),
            ]
            table_data.append(row)

        t = Table(table_data, colWidths=[8*mm, 18*mm, 58*mm, 32*mm, 16*mm, 40*mm])
        ts = TableStyle([
            ('BACKGROUND',    (0,0), (-1,0),  C_NAVY),
            ('TEXTCOLOR',     (0,0), (-1,0),  C_WHITE),
            ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_WHITE, C_SLATE_LIGHT]),
            ('GRID',          (0,0), (-1,-1), 0.3, C_BORDER),
            ('VALIGN',        (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING',    (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING',   (0,0), (-1,-1), 5),
        ])
        t.setStyle(ts)
        els.append(t)

        # Detailed action items below
        els.append(Spacer(1, 6*mm))
        els.append(Paragraph('Detailed Remediation Steps', self.styles['SubHeader']))
        els.append(HRFlowable(width='100%', thickness=0.5, color=C_BORDER))

        for i, rec in enumerate(recs_sorted, 1):
            priority = rec.get('priority', 'Medium')
            pc       = _priority_color(priority)
            els.append(Spacer(1, 3*mm))
            els.append(Paragraph(
                f'<b>{i}. {rec.get("title","")}</b>  '
                f'<font color="{pc.hexval()}" size="8">[{priority}]</font>  '
                f'<font color="#94a3b8" size="8">Effort: {rec.get("effort","?")}  |  '
                f'Pillar: {rec.get("pillar","?")}</font>',
                self.styles['Body']
            ))
            desc = rec.get('description', '')
            if desc:
                els.append(Paragraph(_strip_md(desc), self.styles['BodySmall']))

            risk = rec.get('risk_if_ignored', '')
            if risk:
                els.append(Paragraph(
                    f'<b>Risk if ignored:</b> {_strip_md(risk)}',
                    ParagraphStyle('Risk', parent=self.styles['BodySmall'], textColor=C_HIGH)
                ))

            for j, ai in enumerate(rec.get('action_items', []), 1):
                els.append(Paragraph(f'{j}. {_strip_md(ai)}', self.styles['BulletBody']))

            svcs = rec.get('aws_services', [])
            if svcs:
                els.append(Paragraph(
                    '<b>AWS Services:</b> ' + ', '.join(svcs),
                    self.styles['BodySmall']
                ))
            metric = rec.get('success_metric', '')
            if metric:
                els.append(Paragraph(
                    f'<b>Success Metric:</b> {_strip_md(metric)}',
                    self.styles['BodySmall']
                ))

        return els

    # ── Evidence Appendix ─────────────────────────────────────────────────────

    def _evidence_appendix(self, data: Dict) -> List:
        els = []
        els.append(Paragraph('Appendix A — Evidence Log', self.styles['SectionHeader']))
        els.append(HRFlowable(width='100%', thickness=1, color=C_BLUE))
        els.append(Paragraph(
            'The following table captures the complete question-and-answer log from the assessment '
            'session, including the AI analysis extracted for each response.',
            self.styles['Body']
        ))
        els.append(Spacer(1, 3*mm))

        qa_log = data.get('qa_log', [])
        if not qa_log:
            els.append(Paragraph('No evidence log available.', self.styles['Body']))
            return els

        table_data = [[
            Paragraph('#',           self.styles['TableHeader']),
            Paragraph('QUESTION',    self.styles['TableHeader']),
            Paragraph('ANSWER',      self.styles['TableHeader']),
            Paragraph('MATURITY\nSIGNAL', self.styles['TableHeader']),
            Paragraph('KEY FINDING', self.styles['TableHeader']),
        ]]

        for i, qa in enumerate(qa_log, 1):
            q       = qa.get('question', '')[:120]
            a       = qa.get('answer',   '')[:120]
            analysis= qa.get('analysis', {})
            mat_sig = analysis.get('maturity_signal', '—') if isinstance(analysis, dict) else '—'
            key_pts = analysis.get('key_points', []) if isinstance(analysis, dict) else []
            key_finding = key_pts[0][:80] if key_pts else '—'

            mat_color = _maturity_color(float(mat_sig) if str(mat_sig).isdigit() else 3)

            table_data.append([
                Paragraph(str(i), ParagraphStyle('Num', parent=self.styles['TableCellSmall'],
                    alignment=TA_CENTER)),
                Paragraph(_strip_md(q + ('…' if len(qa.get('question','')) > 120 else '')),
                          self.styles['TableCellSmall']),
                Paragraph(_strip_md(a + ('…' if len(qa.get('answer','')) > 120 else '')),
                          self.styles['TableCellSmall']),
                Paragraph(f'<b><font color="{mat_color.hexval()}">{mat_sig}/5</font></b>',
                          ParagraphStyle('MS', parent=self.styles['TableCellSmall'], alignment=TA_CENTER)),
                Paragraph(_strip_md(key_finding), self.styles['TableCellSmall']),
            ])

        t = Table(table_data, colWidths=[8*mm, 50*mm, 50*mm, 16*mm, 48*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0),  C_NAVY),
            ('TEXTCOLOR',     (0,0), (-1,0),  C_WHITE),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),  [C_WHITE, C_SLATE_LIGHT]),
            ('GRID',          (0,0), (-1,-1), 0.3, C_BORDER),
            ('VALIGN',        (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING',    (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING',   (0,0), (-1,-1), 4),
            ('FONTSIZE',      (0,0), (-1,-1), 7.5),
        ]))
        els.append(t)

        els.append(Spacer(1, 6*mm))
        els.append(Paragraph('End of Report', ParagraphStyle(
            'End', parent=self.styles['Body'], alignment=TA_CENTER,
            textColor=C_SLATE, fontSize=8)))
        return els


# ── Helper functions ──────────────────────────────────────────────────────────

def _pillar_in_analysis(analysis, pillar: str) -> bool:
    """Check if analysis text references a pillar."""
    if isinstance(analysis, dict):
        text = str(analysis.get('evidence_summary', ''))
    else:
        text = str(analysis)
    return pillar.lower() in text.lower()


def _extract_gaps(qa_list: List[Dict]) -> List[str]:
    """Extract Gap bullet points from analysis text."""
    gaps = []
    for qa in qa_list:
        analysis = qa.get('analysis', {})
        if isinstance(analysis, dict):
            gaps.extend(analysis.get('gaps_identified', []))
            # Also parse from evidence_summary
            text = analysis.get('evidence_summary', '')
        else:
            text = str(analysis)
        # Regex: line starting with **Gap:** or - Gap:
        for m in re.finditer(r'(?:\*\*Gap\*\*:|Gap:)\s*(.+?)(?:\n|$)', text, re.IGNORECASE):
            g = m.group(1).strip()
            if g and g not in gaps:
                gaps.append(g)
    return gaps[:8]


def _extract_risks(qa_list: List[Dict]) -> List[str]:
    """Extract Risk bullet points from analysis text."""
    risks = []
    for qa in qa_list:
        analysis = qa.get('analysis', {})
        text = ''
        if isinstance(analysis, dict):
            text = analysis.get('evidence_summary', '')
        else:
            text = str(analysis)
        for m in re.finditer(r'(?:\*\*Risk\*\*:)\s*(.+?)(?:\n|$)', text, re.IGNORECASE):
            r = m.group(1).strip()
            if r and r not in risks:
                risks.append(r)
    return risks[:5]

import io
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether

def generate_pdf_report(email_data: Dict[str, Any]) -> bytes:
    """
    Generates a PDF forensic threat report for the analyzed email and returns it as bytes.
    email_data is expected to contain:
      - id: int
      - sender: str
      - sender_domain: str
      - subject: str
      - verdict: str (SAFE, SUSPICIOUS, MALICIOUS)
      - threat_score: int (0 to 100)
      - rule_score: int
      - confidence: str
      - received_at: str or datetime
      - spf_status: str
      - dkim_status: str
      - dmarc_status: str
      - urls: list of dicts (url, domain, vt_score, is_phishing)
      - ips: list of dicts (ip, abuse_score, spamhaus_flagged, is_malicious)
      - attachments: list of dicts (file_name, sha256, vt_score)
      - timeline: list of dicts (timestamp, event_type, description, severity)
      - rule_details: list of strings (rules triggered)
    """
    buffer = io.BytesIO()
    
    # Initialize document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    story = []
    
    # Set up styles
    styles = getSampleStyleSheet()
    
    # Define custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#1A2530"),
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#7F8C8D"),
        spaceAfter=20
    )
    
    h1_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#2C3E50"),
        spaceBefore=15,
        spaceAfter=8,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#34495E")
    )
    
    bold_body_style = ParagraphStyle(
        'ReportBodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=9,
        leading=11,
        textColor=colors.HexColor("#272822")
    )

    # Verdict Colors
    verdict = email_data.get("verdict", "SAFE").upper()
    if verdict == "MALICIOUS":
        verdict_color = colors.HexColor("#E74C3C")
    elif verdict == "SUSPICIOUS":
        verdict_color = colors.HexColor("#F39C12")
    else:
        verdict_color = colors.HexColor("#2ECC71")
        
    # --- HEADER SECTION ---
    story.append(Paragraph("EMAIL FORENSIC ANALYSIS REPORT", title_style))
    story.append(Paragraph(f"Advanced Email Threat Intelligence Platform | Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
    story.append(Spacer(1, 10))
    
    # --- SCORE & VERDICT SUMMARY GRID ---
    summary_data = [
        [
            Paragraph("<b>Verdict:</b>", body_style),
            Paragraph(f"<font color='{verdict_color.hexval()}'><b>{verdict}</b></font>", bold_body_style),
            Paragraph("<b>Email ID:</b>", body_style),
            Paragraph(str(email_data.get("id", "N/A")), body_style)
        ],
        [
            Paragraph("<b>Threat Score:</b>", body_style),
            Paragraph(f"<b>{email_data.get('threat_score', 0)} / 100</b>", bold_body_style),
            Paragraph("<b>Confidence:</b>", body_style),
            Paragraph(email_data.get("confidence", "LOW"), body_style)
        ]
    ]
    
    summary_table = Table(summary_data, colWidths=[1.5*inch, 2*inch, 1.5*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8F9FA")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#ECF0F1")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))
    
    # --- EMAIL METADATA SECTION ---
    story.append(Paragraph("Email Metadata", h1_style))
    
    received_time = email_data.get("received_at")
    if isinstance(received_time, datetime):
        received_str = received_time.strftime("%Y-%m-%d %H:%M:%S")
    else:
        received_str = str(received_time or "N/A")
        
    meta_data = [
        [Paragraph("<b>Sender:</b>", body_style), Paragraph(email_data.get("sender", "N/A"), body_style)],
        [Paragraph("<b>Sender Domain:</b>", body_style), Paragraph(email_data.get("sender_domain", "N/A"), body_style)],
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(email_data.get("subject", "N/A"), body_style)],
        [Paragraph("<b>Received Date:</b>", body_style), Paragraph(received_str, body_style)],
    ]
    
    meta_table = Table(meta_data, colWidths=[1.5*inch, 5.5*inch])
    meta_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('LINEBELOW', (0,0), (-1,-2), 0.5, colors.HexColor("#EAECEE")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))
    
    # --- EMAIL SECURITY PROTOCOLS ---
    story.append(Paragraph("Authentication Protocols (SPF / DKIM / DMARC)", h1_style))
    
    def get_auth_html(status: str) -> str:
        status_clean = str(status or "NONE").upper()
        if status_clean in ["PASS", "SUCCESS"]:
            return f"<font color='green'><b>{status_clean}</b></font>"
        elif status_clean in ["FAIL", "FAILED", "SOFTFAIL"]:
            return f"<font color='red'><b>{status_clean}</b></font>"
        else:
            return f"<font color='gray'><b>{status_clean}</b></font>"
            
    auth_data = [
        [
            Paragraph("<b>SPF (Sender Policy Framework)</b>", body_style),
            Paragraph(get_auth_html(email_data.get("spf_status")), body_style)
        ],
        [
            Paragraph("<b>DKIM (DomainKeys Identified Mail)</b>", body_style),
            Paragraph(get_auth_html(email_data.get("dkim_status")), body_style)
        ],
        [
            Paragraph("<b>DMARC (Domain-based Message Authentication)</b>", body_style),
            Paragraph(get_auth_html(email_data.get("dmarc_status")), body_style)
        ],
    ]
    
    auth_table = Table(auth_data, colWidths=[3.5*inch, 3.5*inch])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#FDFEFE")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('LINEBELOW', (0,0), (-1,-2), 0.5, colors.HexColor("#EAECEE")),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 15))
    
    # --- EXTRACTED IOCS SECTION ---
    iocs_story = []
    iocs_story.append(Paragraph("Indicators of Compromise (IOC) Analysis", h1_style))
    
    # 1. URLs
    urls = email_data.get("urls", [])
    if urls:
        iocs_story.append(Paragraph("<b>Analyzed URLs</b>", bold_body_style))
        url_table_data = [["URL / Domain", "VirusTotal Score", "Verdict"]]
        for u in urls[:10]: # Limit to top 10 URLs
            vt_score = u.get("vt_score", 0)
            verdict_text = "Phishing/Malicious" if u.get("is_phishing") else "Harmless"
            verdict_color_str = "red" if u.get("is_phishing") else "green"
            
            url_table_data.append([
                Paragraph(f"<font size='8'>{u.get('url', 'N/A')[:60]}...</font>", body_style),
                Paragraph(str(vt_score), body_style),
                Paragraph(f"<font color='{verdict_color_str}'>{verdict_text}</font>", body_style)
            ])
            
        url_table = Table(url_table_data, colWidths=[4.2*inch, 1.3*inch, 1.5*inch])
        url_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2C3E50")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8F9FA")]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
        ]))
        iocs_story.append(url_table)
        iocs_story.append(Spacer(1, 10))
        
    # 2. IPs
    ips = email_data.get("ips", [])
    if ips:
        iocs_story.append(Paragraph("<b>Sender & Relay IPs</b>", bold_body_style))
        ip_table_data = [["IP Address", "Abuse Score", "Spamhaus Blacklisted", "Verdict"]]
        for ip in ips[:10]:
            abuse = ip.get("abuse_score", 0)
            blacklisted = "YES" if ip.get("spamhaus_flagged") else "NO"
            ip_verdict = "Malicious" if ip.get("is_malicious") or ip.get("spamhaus_flagged") else "Clean"
            ip_color = "red" if ip_verdict == "Malicious" else "green"
            
            ip_table_data.append([
                Paragraph(ip.get("ip", "N/A"), body_style),
                Paragraph(f"{abuse}%", body_style),
                Paragraph(blacklisted, body_style),
                Paragraph(f"<font color='{ip_color}'>{ip_verdict}</font>", body_style)
            ])
            
        ip_table = Table(ip_table_data, colWidths=[2.2*inch, 1.5*inch, 1.8*inch, 1.5*inch])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2C3E50")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8F9FA")]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
        ]))
        iocs_story.append(ip_table)
        iocs_story.append(Spacer(1, 10))
        
    # 3. Attachments
    attachments = email_data.get("attachments", [])
    if attachments:
        iocs_story.append(Paragraph("<b>Extracted Attachments</b>", bold_body_style))
        att_table_data = [["File Name", "SHA256 Hash", "VT Score"]]
        for att in attachments[:10]:
            vt_score = att.get("vt_score", 0)
            vt_score_str = str(vt_score) if vt_score > 0 else "Clean / Unreported"
            att_table_data.append([
                Paragraph(att.get("file_name", "N/A"), body_style),
                Paragraph(f"<font size='8'>{att.get('sha256', 'N/A')}</font>", code_style),
                Paragraph(vt_score_str, body_style)
            ])
            
        att_table = Table(att_table_data, colWidths=[2.2*inch, 3.5*inch, 1.3*inch])
        att_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2C3E50")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8F9FA")]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
        ]))
        iocs_story.append(att_table)
        
    if urls or ips or attachments:
        story.append(KeepTogether(iocs_story))
        story.append(Spacer(1, 15))
        
    # --- TRIGGERED RULES ---
    rule_details = email_data.get("rule_details", [])
    if rule_details:
        rules_story = []
        rules_story.append(Paragraph("Triggered Detection Rules", h1_style))
        for rule in rule_details:
            rules_story.append(Paragraph(f"• {rule}", body_style))
        story.append(KeepTogether(rules_story))
        story.append(Spacer(1, 15))
        
    # --- FORENSIC TIMELINE SECTION ---
    timeline = email_data.get("timeline", [])
    if timeline:
        timeline_story = []
        timeline_story.append(Paragraph("Forensic Event Timeline", h1_style))
        timeline_table_data = [["Timestamp", "Event Type", "Severity", "Description"]]
        
        for event in timeline:
            ts = event.get("timestamp", "N/A")
            if isinstance(ts, datetime):
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
            else:
                ts_str = str(ts)
                
            severity = event.get("severity", "INFO").upper()
            sev_color = "red" if severity == "ERROR" else ("orange" if severity == "WARNING" else "black")
            
            timeline_table_data.append([
                Paragraph(ts_str, body_style),
                Paragraph(event.get("event_type", "N/A"), body_style),
                Paragraph(f"<font color='{sev_color}'><b>{severity}</b></font>", body_style),
                Paragraph(event.get("description", "N/A"), body_style)
            ])
            
        timeline_table = Table(timeline_table_data, colWidths=[1.8*inch, 1.4*inch, 0.8*inch, 3.0*inch])
        timeline_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#34495E")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8F9FA")]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
        ]))
        timeline_story.append(timeline_table)
        story.append(KeepTogether(timeline_story))
        
    # Build Document
    doc.build(story)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

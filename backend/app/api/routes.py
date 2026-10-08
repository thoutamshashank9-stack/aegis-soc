"""
FastAPI Router for Analysis Endpoints.
Provides:
- POST /api/analyze (File upload .eml)
- POST /api/analyze/text (Raw email text or headers+body)
- GET /api/analysis/{id} (Retrieve past investigation)
- GET /api/analyses (List historical investigations)
- GET /api/analysis/{id}/report (Comprehensive structured intelligence report)
- GET /api/analysis/{id}/iocs (Export IOCs in structured format)
- GET /api/health (System and dependency health check)
- GET /api/ml/status (ML model and evaluation metrics status)
- GET /api/system/status (Database & system status)
"""
import uuid
import datetime
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from app.database.models import (
    get_db, EmailAnalysis, EmailHeader, ThreatFinding, IOC,
    GeolocationResult, ForensicEvent, Report
)
from app.models.schemas import (
    AnalyzeTextRequest, AnalysisResponse, AnalysisListItem,
    ThreatFindingSchema, URLFindingSchema, AttachmentSchema,
    GeolocationSchema, HopSchema, TimelineEventSchema, MLResultSchema
)
from app.services.email_analyzer import EmailAnalyzer
from app.services.url_analyzer import URLAnalyzer
from app.services.attachment_analyzer import AttachmentAnalyzer
from app.services.geolocation_service import GeolocationService
from app.services.ml_service import MLClassifierService
from app.services.threat_engine import ThreatEngine
from app.forensic.forensic_engine import ForensicEngine

router = APIRouter(prefix="/api", tags=["Threat Intelligence"])


def _process_email_pipeline(raw_bytes: bytes, filename: str, db: Session) -> Dict[str, Any]:
    # 1. Hashing
    sha256 = ForensicEngine.calculate_sha256(raw_bytes)
    file_size = len(raw_bytes)

    # 2. Parsing
    email_data = EmailAnalyzer.parse_raw_bytes(raw_bytes)

    # 3. URL Analysis
    url_results = URLAnalyzer.analyze_urls(email_data["urls"], sender_domain=email_data["sender_domain"])

    # 4. Attachment Analysis
    attachment_results = AttachmentAnalyzer.analyze_attachments(email_data["attachments"], raw_bytes=raw_bytes)

    # 5. ML Classification
    ml_res = MLClassifierService.predict(email_data["subject"], email_data["body_text"])

    # 6. Threat Detection & Risk Scoring
    threat_res = ThreatEngine.analyze_threats(email_data, url_results, attachment_results, ml_res)

    # 7. Geolocation Intelligence
    geo_results = []
    # Identify unique IPs
    seen_ips = set()
    for ip_item in email_data["ips"]:
        ip_addr = ip_item["ip"]
        if ip_addr not in seen_ips:
            seen_ips.add(ip_addr)
            geo = GeolocationService.geolocate_ip(
                ip_str=ip_addr,
                ip_type=ip_item.get("type"),
                source=ip_item.get("source"),
                source_header=ip_item.get("header"),
                hop_order=ip_item.get("hop_order"),
                total_hops=ip_item.get("total_hops"),
                from_host=ip_item.get("from_host"),
                by_host=ip_item.get("by_host"),
                raw_timestamp=ip_item.get("raw_timestamp")
            )
            geo_results.append(geo)

    # 8. Forensic MTA Chain & Timeline
    hops = ForensicEngine.analyze_header_chain(email_data["received_headers"])
    timeline = ForensicEngine.build_forensic_timeline(email_data, hops)

    # 9. IOC Extraction
    iocs = ForensicEngine.extract_iocs(email_data, url_results, sha256)

    # 10. Persist into Database
    analysis_id = str(uuid.uuid4())
    analyzed_at = datetime.datetime.now(datetime.timezone.utc)

    db_analysis = EmailAnalysis(
        id=analysis_id,
        filename=filename,
        file_size_bytes=file_size,
        sha256=sha256,
        analyzed_at=analyzed_at,
        sender=email_data["sender"],
        sender_display=email_data["sender_display"],
        sender_domain=email_data["sender_domain"],
        recipient=email_data["recipient"],
        subject=email_data["subject"],
        message_id=email_data["message_id"],
        return_path=email_data["return_path"],
        reply_to=email_data["reply_to"],
        date_header=email_data.get("date"),
        auth_spf=email_data.get("authentication", {}).get("spf", "unknown"),
        auth_dkim=email_data.get("authentication", {}).get("dkim", "unknown"),
        auth_dmarc=email_data.get("authentication", {}).get("dmarc", "unknown"),
        urls_data=url_results,
        attachments_data=attachment_results,
        timeline_data=timeline,
        ml_prediction=ml_res.get("prediction", "unknown"),
        ml_confidence=ml_res.get("confidence", 0.0),
        ml_probabilities=ml_res.get("probabilities", {}),
        risk_score=threat_res["risk_score"],
        risk_level=threat_res["risk_level"],
        executive_summary=threat_res["executive_summary"]
    )
    db.add(db_analysis)

    # Store findings
    for finding in threat_res["findings"]:
        tf = ThreatFinding(
            analysis_id=analysis_id,
            indicator=finding["indicator"],
            severity=finding["severity"],
            reason=finding["reason"],
            evidence=finding.get("evidence")
        )
        db.add(tf)

    # Store Geolocation
    for g in geo_results:
        gr = GeolocationResult(
            analysis_id=analysis_id,
            ip=g["ip"],
            is_private_or_reserved=not g.get("is_public", True),
            country=g.get("country", "Unknown"),
            region=g.get("region", "Unknown"),
            city=g.get("city", "Unknown"),
            latitude=g.get("latitude"),
            longitude=g.get("longitude"),
            isp=g.get("isp", "Unknown"),
            asn=g.get("asn", "Unknown"),
            org=g.get("org", "Unknown"),
            timezone=g.get("timezone", "Unknown"),
            lookup_status=g.get("lookup_status", "success")
        )
        db.add(gr)

    # Store Hops / Forensic Events
    for h in hops:
        fe = ForensicEvent(
            analysis_id=analysis_id,
            hop_order=h["hop_order"],
            raw_timestamp=h.get("raw_timestamp"),
            from_host=h.get("from_host", "Unknown"),
            by_host=h.get("by_host", "Unknown"),
            relay_ip=h.get("relay_ip"),
            notes=h.get("raw_header_snippet")
        )
        db.add(fe)

    # Store IOCs
    for category, items in iocs.items():
        for it in items:
            ioc_entry = IOC(
                analysis_id=analysis_id,
                ioc_type=category,
                ioc_value=it.get("value", ""),
                threat_level="suspicious"
            )
            db.add(ioc_entry)

    db.commit()

    return {
        "id": analysis_id,
        "filename": filename,
        "file_size_bytes": file_size,
        "sha256": sha256,
        "analyzed_at": analyzed_at.isoformat(),
        "sender": email_data["sender"],
        "sender_email": email_data["sender_email"],
        "sender_display": email_data["sender_display"],
        "sender_domain": email_data["sender_domain"],
        "recipient": email_data["recipient"],
        "subject": email_data["subject"],
        "message_id": email_data["message_id"],
        "return_path": email_data["return_path"],
        "reply_to": email_data["reply_to"],
        "date": email_data["date"],
        "authentication": email_data["authentication"],
        "threat_findings": threat_res["findings"],
        "risk_score": threat_res["risk_score"],
        "risk_level": threat_res["risk_level"],
        "executive_summary": threat_res["executive_summary"],
        "ml_result": ml_res,
        "urls": url_results,
        "attachments": attachment_results,
        "ips": email_data["ips"],
        "geolocations": geo_results,
        "forensic_hops": hops,
        "timeline": timeline,
        "iocs": iocs
    }


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Analyzes an uploaded .eml or raw email file."""
    # Maximum file size 15MB to prevent memory exhaustion
    contents = await file.read()
    if len(contents) > 15 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (exceeds 15MB limit)")
    
    filename = file.filename or "uploaded_email.eml"
    return _process_email_pipeline(contents, filename, db)


@router.post("/analyze/text", response_model=AnalysisResponse)
def analyze_text(
    payload: AnalyzeTextRequest,
    db: Session = Depends(get_db)
):
    """Analyzes pasted raw email text."""
    if not payload.raw_text.strip():
        raise HTTPException(status_code=400, detail="Provided email text is empty")
    
    raw_bytes = payload.raw_text.encode("utf-8", errors="replace")
    return _process_email_pipeline(raw_bytes, payload.filename or "pasted_email.eml", db)


@router.get("/analyses", response_model=List[AnalysisListItem])
def list_analyses(db: Session = Depends(get_db)):
    """Retrieves all past email investigations."""
    records = db.query(EmailAnalysis).order_by(EmailAnalysis.analyzed_at.desc()).limit(100).all()
    results = []
    for r in records:
        results.append({
            "id": r.id,
            "filename": r.filename or "unknown.eml",
            "subject": r.subject or "(No Subject)",
            "sender_email": r.sender or "unknown",
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "ml_prediction": r.ml_prediction,
            "analyzed_at": r.analyzed_at.isoformat() if r.analyzed_at else ""
        })
    return results


@router.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Computes dynamic aggregate metrics across all database records directly via SQL."""
    total = db.query(EmailAnalysis).count()
    critical = db.query(EmailAnalysis).filter(EmailAnalysis.risk_level == "CRITICAL").count()
    high = db.query(EmailAnalysis).filter(EmailAnalysis.risk_level == "HIGH").count()
    medium = db.query(EmailAnalysis).filter(EmailAnalysis.risk_level == "MEDIUM").count()
    low = db.query(EmailAnalysis).filter(EmailAnalysis.risk_level == "LOW").count()
    phishing = db.query(EmailAnalysis).filter(EmailAnalysis.ml_prediction == "phishing").count()
    spam = db.query(EmailAnalysis).filter(EmailAnalysis.ml_prediction == "spam").count()
    legitimate = db.query(EmailAnalysis).filter(EmailAnalysis.ml_prediction == "legitimate").count()

    return {
        "total_ingested": total,
        "critical_threats": critical,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low,
        "phishing_detections": phishing,
        "spam_detections": spam,
        "legitimate_emails": legitimate
    }


@router.get("/analysis/{analysis_id}")
def get_analysis_details(analysis_id: str, db: Session = Depends(get_db)):
    """Retrieves complete details of a specific investigation."""
    analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Investigation record not found")

    findings = [
        {"indicator": f.indicator, "severity": f.severity, "reason": f.reason, "evidence": f.evidence}
        for f in analysis.threat_findings
    ]
    hops = [
        {
            "hop_order": h.hop_order,
            "from_host": h.from_host,
            "by_host": h.by_host,
            "relay_ip": h.relay_ip or "none",
            "raw_timestamp": h.raw_timestamp or "unknown",
            "iso_timestamp": None,
            "raw_header_snippet": h.notes
        }
        for h in sorted(analysis.forensic_events, key=lambda x: x.hop_order)
    ]
    total_hops_count = len(hops)

    geos = []
    for g in analysis.geolocations:
        matching_hop = next((h for h in hops if h["relay_ip"] == g.ip), None)
        geo_item = GeolocationService.geolocate_ip(
            ip_str=g.ip,
            source="Received" if matching_hop else "Email",
            source_header=matching_hop["raw_header_snippet"] if matching_hop else None,
            hop_order=matching_hop["hop_order"] if matching_hop else None,
            total_hops=total_hops_count,
            from_host=matching_hop["from_host"] if matching_hop else None,
            by_host=matching_hop["by_host"] if matching_hop else None,
            raw_timestamp=matching_hop["raw_timestamp"] if matching_hop else None,
        )
        geos.append(geo_item)

    iocs_grouped = {"ips": [], "domains": [], "urls": [], "emails": [], "hashes": [], "attachments": []}
    for i in analysis.iocs:
        if i.ioc_type in iocs_grouped:
            iocs_grouped[i.ioc_type].append({"value": i.ioc_value, "threat_level": i.threat_level})

    return {
        "id": analysis.id,
        "filename": analysis.filename,
        "file_size_bytes": analysis.file_size_bytes,
        "sha256": analysis.sha256,
        "analyzed_at": analysis.analyzed_at.isoformat() if analysis.analyzed_at else "",
        "sender": analysis.sender,
        "sender_email": analysis.sender,
        "sender_display": analysis.sender_display,
        "sender_domain": analysis.sender_domain,
        "recipient": analysis.recipient,
        "subject": analysis.subject,
        "message_id": analysis.message_id,
        "return_path": analysis.return_path,
        "reply_to": analysis.reply_to,
        "date": analysis.date_header or "not_available",
        "authentication": {
            "spf": analysis.auth_spf or "unknown",
            "dkim": analysis.auth_dkim or "unknown",
            "dmarc": analysis.auth_dmarc or "unknown"
        },
        "threat_findings": findings,
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "executive_summary": analysis.executive_summary,
        "ml_result": {
            "prediction": analysis.ml_prediction,
            "confidence": analysis.ml_confidence,
            "probabilities": analysis.ml_probabilities or {},
            "model_available": True
        },
        "urls": analysis.urls_data or [],
        "attachments": analysis.attachments_data or [],
        "ips": [
            {
                "ip": g["ip"],
                "source": "Received",
                "header": None,
                "type": g["ip_type"],
                "hop_index": None,
                "is_private": not g["is_public"]
            }
            for g in geos
        ],
        "geolocations": geos,
        "forensic_hops": hops,
        "timeline": analysis.timeline_data or [],
        "iocs": iocs_grouped
    }


@router.get("/analysis/{analysis_id}/report")
def get_analysis_report(analysis_id: str, db: Session = Depends(get_db)):
    """Generates an executive SOC forensic report."""
    analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    existing_report = db.query(Report).filter(Report.analysis_id == analysis_id).first()
    if existing_report and existing_report.report_data:
        return existing_report.report_data

    report_payload = {
        "title": "EXECUTIVE EMAIL FORENSIC & THREAT INTELLIGENCE REPORT",
        "report_id": analysis.id,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "evidence_integrity": {
            "filename": analysis.filename,
            "sha256": analysis.sha256,
            "size_bytes": analysis.file_size_bytes
        },
        "verdict": {
            "risk_score": analysis.risk_score,
            "risk_level": analysis.risk_level,
            "ml_classification": analysis.ml_prediction,
            "ml_confidence": analysis.ml_confidence,
            "executive_summary": analysis.executive_summary
        },
        "authentication": {
            "spf": analysis.auth_spf or "unknown",
            "dkim": analysis.auth_dkim or "unknown",
            "dmarc": analysis.auth_dmarc or "unknown"
        },
        "sender_metadata": {
            "claimed_sender": analysis.sender,
            "display_name": analysis.sender_display,
            "sender_domain": analysis.sender_domain,
            "recipient": analysis.recipient,
            "subject": analysis.subject,
            "message_id": analysis.message_id,
            "reply_to": analysis.reply_to,
            "return_path": analysis.return_path
        },
        "key_threat_indicators": [
            {"indicator": tf.indicator, "severity": tf.severity, "reason": tf.reason, "evidence": tf.evidence}
            for tf in analysis.threat_findings
        ],
        "geolocation_findings": [
            {
                "ip": g.ip,
                "country": g.country,
                "city": g.city,
                "isp": g.isp,
                "asn": g.asn,
                "notice": "Approximate geolocation from routing hops."
            }
            for g in analysis.geolocations
        ],
        "limitations_notice": [
            "IP geolocation represents approximate routing infrastructure and does not pinpoint the sender's physical address.",
            "Authentication results rely on header records and public DNS posture at time of transmission.",
            "All intelligence verdicts are probabilistically determined from multi-layered deterministic and NLP heuristic evaluation."
        ]
    }
    db.add(Report(analysis_id=analysis_id, report_data=report_payload))
    db.commit()
    return report_payload


@router.get("/analysis/{analysis_id}/iocs")
def get_analysis_iocs(analysis_id: str, db: Session = Depends(get_db)):
    """Exports structured IOC indicators."""
    analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    iocs = db.query(IOC).filter(IOC.analysis_id == analysis_id).all()
    grouped = {}
    for item in iocs:
        grouped.setdefault(item.ioc_type, []).append(item.ioc_value)

    return {
        "analysis_id": analysis_id,
        "sha256": analysis.sha256,
        "total_iocs": len(iocs),
        "indicators": grouped
    }


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AI Email Threat Detection & Forensic Intelligence Platform",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


@router.get("/ml/status")
def ml_status():
    return MLClassifierService.get_status()


@router.get("/system/status")
def system_status(db: Session = Depends(get_db)):
    analyses_count = db.query(EmailAnalysis).count()
    return {
        "database": "online",
        "total_investigations_stored": analyses_count,
        "services": {
            "email_parser": "RFC 5322 Compliant",
            "threat_engine": "Active (Rules + ML + Heuristics)",
            "url_analyzer": "Active",
            "attachment_analyzer": "Active (Zero-execution sandbox)",
            "geolocation": "Active (ip-api / fallback)",
            "ml_classifier": "Active (TF-IDF Logistic Regression)"
        }
    }


import os

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "sample_emails"))

@router.get("/samples")
def list_samples():
    """Lists available synthetic demo test emails."""
    if not os.path.exists(SAMPLES_DIR):
        return []
    files = [f for f in os.listdir(SAMPLES_DIR) if f.endswith(".eml")]
    sample_list = []
    descriptions = {
        "test_a_no_received_demo.eml": "Test A: Direct email with No Received headers (Clean RFC 5322 metadata, 0 hops)",
        "test_b_private_ip_demo.eml": "Test B: Internal relay with RFC 1918 Private IP (10.240.12.88 - Not geolocatable)",
        "test_c_documentation_ip_demo.eml": "Test C: Testbed with RFC 5737 Documentation IP (198.51.100.42 - Not geolocatable)",
        "test_d_public_ip_demo.eml": "Test D: Valid public routable IP (8.8.8.8 - Live Geolocation & Coordinates)",
        "test_e_multi_hop_demo.eml": "Test E: Multi-hop relay traversal (Documentation + Public + Private hops)",
        "phishing_demo.eml": "Phishing attack (Office 365 credential harvesting with SPF/DKIM/DMARC failure & malicious link)",
        "legitimate_demo.eml": "Legitimate transaction (GitHub PR merge notification with verified SPF/DKIM/DMARC pass)",
        "suspicious_auth_demo.eml": "Authentication spoofing (Bank alert with softfail & unroutable private IP link)",
        "suspicious_attachment_demo.eml": "Malware dropper (Contract invoice with executable double-extension .pdf.exe)",
        "header_anomaly_demo.eml": "CEO Fraud / BEC (Display name impersonation with mismatched Reply-To and Return-Path)",
        "spam_demo.eml": "Bulk unsolicited spam (Miracle weight-loss discount promotion)"
    }
    for f in sorted(files):
        sample_list.append({
            "filename": f,
            "description": descriptions.get(f, "Synthetic test email"),
            "size_bytes": os.path.getsize(os.path.join(SAMPLES_DIR, f))
        })
    return sample_list


@router.get("/samples/{filename}")
def get_sample_content(filename: str):
    """Retrieves the raw content of a synthetic demo test email."""
    # Prevent path traversal
    safe_name = os.path.basename(filename)
    file_path = os.path.join(SAMPLES_DIR, safe_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Sample email not found")
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    return {
        "filename": safe_name,
        "content": content
    }

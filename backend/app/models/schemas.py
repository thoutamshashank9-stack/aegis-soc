"""
Pydantic Schemas for API Request and Response validation.
"""
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime


class AnalyzeTextRequest(BaseModel):
    raw_text: str = Field(..., description="Raw RFC 5322 email string or headers+body")
    filename: Optional[str] = Field("pasted_email.eml", description="Optional virtual filename")


class AuthenticationStatus(BaseModel):
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"


class ThreatFindingSchema(BaseModel):
    indicator: str
    severity: str
    reason: str
    evidence: Optional[str] = None


class URLFindingSchema(BaseModel):
    url: str
    host: str
    scheme: str
    is_suspicious: bool
    indicators: List[Dict[str, Any]] = []
    reputation_provider: str = "External lookup unavailable"


class AttachmentSchema(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    is_dangerous: bool
    is_archive: bool
    double_extension: bool
    reasons: List[str] = []


class IPRecordSchema(BaseModel):
    ip: str
    source: str = "Received"
    header: Optional[str] = None
    type: str = "unknown"
    hop_index: Optional[int] = None
    hop_order: Optional[int] = None
    total_hops: Optional[int] = None
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    raw_timestamp: Optional[str] = None
    why_it_matters: Optional[str] = None
    is_private: Optional[bool] = None


class GeolocationSchema(BaseModel):
    ip: str
    source: Optional[str] = "Received"
    source_header: Optional[str] = None
    hop_order: Optional[int] = None
    total_hops: Optional[int] = None
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    raw_timestamp: Optional[str] = None
    
    is_public: bool
    is_geolocatable: bool = True
    ip_type: str
    not_geolocatable_reason: Optional[str] = None
    
    infrastructure_type: str = "Unknown"
    infrastructure_tag: str = "Network"
    infrastructure_context: Optional[str] = None
    
    relay_role: str = "Mail Relay"
    why_it_matters: str = "Mail routing infrastructure."
    confidence_score: int = 0
    confidence_label: str = "Unrated"
    forensic_explanation: str = "Extracted from message transit records."
    
    network_location: str = "Unknown"
    network_location_type: str = "Server Infrastructure"
    relay_location: str = "Mail Server"
    sender_physical_location: str = "UNVERIFIED / NOT DETERMINABLE FROM IP"
    sender_location_disclaimer: str = (
        "FORENSIC PRINCIPLE: Mail server IP addresses identify mail transfer infrastructure (server data centers, "
        "cloud hosts, or relay gateways). They NEVER prove the physical home or office location of the human sender."
    )
    
    country: str = "Unknown"
    region: str = "Unknown"
    city: str = "Unknown"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: str = "Unknown"
    asn: str = "Unknown"
    org: str = "Unknown"
    timezone: str = "Unknown"
    lookup_status: str = "success"
    accuracy_notice: str


class HopSchema(BaseModel):
    hop_order: int
    from_host: str
    by_host: str
    relay_ip: str
    raw_timestamp: str
    iso_timestamp: Optional[str] = None
    raw_header_snippet: Optional[str] = None


class TimelineEventSchema(BaseModel):
    stage: str
    timestamp: Optional[str] = None
    description: str
    component: str
    type: str


class MLResultSchema(BaseModel):
    prediction: str
    confidence: float
    probabilities: Dict[str, float] = {}
    model_available: bool
    model_name: Optional[str] = None
    note: Optional[str] = None


class AnalysisResponse(BaseModel):
    id: str
    filename: str
    file_size_bytes: int
    sha256: str
    analyzed_at: str
    
    sender: str
    sender_email: str
    sender_display: str
    sender_domain: str
    recipient: str
    subject: str
    message_id: str
    return_path: str
    reply_to: str
    date: str
    
    authentication: AuthenticationStatus
    threat_findings: List[ThreatFindingSchema]
    risk_score: int
    risk_level: str
    executive_summary: str
    
    ml_result: MLResultSchema
    urls: List[URLFindingSchema]
    attachments: List[AttachmentSchema]
    ips: List[IPRecordSchema] = []
    geolocations: List[GeolocationSchema]
    forensic_hops: List[HopSchema]
    timeline: List[TimelineEventSchema]
    iocs: Dict[str, List[Any]]


class AnalysisListItem(BaseModel):
    id: str
    filename: str
    subject: str
    sender_email: str
    risk_score: int
    risk_level: str
    ml_prediction: str
    analyzed_at: str

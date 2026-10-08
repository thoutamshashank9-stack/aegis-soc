"""
SQLAlchemy database setup and schema definitions.
Supports PostgreSQL (via env DATABASE_URL) and clean SQLite fallback for local development.
"""
import os
import datetime
from sqlalchemy import (
    create_engine, Column, String, Integer, Float, Text, Boolean, DateTime, ForeignKey, JSON
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./email_threat_intelligence.db")

# SQLite needs connect_args check_same_thread=False
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    role = Column(String(50), default="analyst")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class EmailAnalysis(Base):
    __tablename__ = "email_analysis"
    id = Column(String(64), primary_key=True, index=True)  # UUID or Hash
    filename = Column(String(255), nullable=True)
    file_size_bytes = Column(Integer, default=0)
    sha256 = Column(String(64), index=True, nullable=False)
    analyzed_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    sender = Column(String(255), nullable=True)
    sender_display = Column(String(255), nullable=True)
    sender_domain = Column(String(255), nullable=True)
    recipient = Column(String(255), nullable=True)
    subject = Column(String(500), nullable=True)
    message_id = Column(String(255), nullable=True)
    return_path = Column(String(255), nullable=True)
    reply_to = Column(String(255), nullable=True)
    
    # ML Classification
    ml_prediction = Column(String(50), default="unknown")
    ml_confidence = Column(Float, default=0.0)
    ml_probabilities = Column(JSON, default=dict)
    
    # Risk Scoring
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="LOW")
    executive_summary = Column(Text, nullable=True)

    # Authentication Verification Results
    auth_spf = Column(String(50), default="unknown")
    auth_dkim = Column(String(50), default="unknown")
    auth_dmarc = Column(String(50), default="unknown")
    date_header = Column(String(255), nullable=True)

    # Structured Data Payloads
    urls_data = Column(JSON, default=list)
    attachments_data = Column(JSON, default=list)
    timeline_data = Column(JSON, default=list)

    # Relationships
    headers = relationship("EmailHeader", back_populates="analysis", cascade="all, delete-orphan")
    threat_findings = relationship("ThreatFinding", back_populates="analysis", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="analysis", cascade="all, delete-orphan")
    geolocations = relationship("GeolocationResult", back_populates="analysis", cascade="all, delete-orphan")
    forensic_events = relationship("ForensicEvent", back_populates="analysis", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="analysis", cascade="all, delete-orphan")


class EmailHeader(Base):
    __tablename__ = "email_headers"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("email_analysis.id"), nullable=False)
    header_name = Column(String(255), nullable=False)
    header_value = Column(Text, nullable=False)
    
    analysis = relationship("EmailAnalysis", back_populates="headers")


class ThreatFinding(Base):
    __tablename__ = "threat_findings"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("email_analysis.id"), nullable=False)
    indicator = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    reason = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)

    analysis = relationship("EmailAnalysis", back_populates="threat_findings")


class IOC(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("email_analysis.id"), nullable=False)
    ioc_type = Column(String(50), nullable=False)  # ip, domain, url, email, hash, filename
    ioc_value = Column(String(1000), nullable=False)
    threat_level = Column(String(20), default="suspicious")

    analysis = relationship("EmailAnalysis", back_populates="iocs")


class GeolocationResult(Base):
    __tablename__ = "geolocation_results"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("email_analysis.id"), nullable=False)
    ip = Column(String(50), nullable=False)
    is_private_or_reserved = Column(Boolean, default=False)
    country = Column(String(100), default="Unknown")
    region = Column(String(100), default="Unknown")
    city = Column(String(100), default="Unknown")
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    isp = Column(String(255), default="Unknown")
    asn = Column(String(100), default="Unknown")
    org = Column(String(255), default="Unknown")
    timezone = Column(String(100), default="Unknown")
    lookup_status = Column(String(50), default="success")

    analysis = relationship("EmailAnalysis", back_populates="geolocations")


class ForensicEvent(Base):
    __tablename__ = "forensic_events"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("email_analysis.id"), nullable=False)
    hop_order = Column(Integer, default=0)
    event_timestamp = Column(DateTime, nullable=True)
    raw_timestamp = Column(String(255), nullable=True)
    from_host = Column(String(255), default="Unknown")
    by_host = Column(String(255), default="Unknown")
    protocol = Column(String(50), default="SMTP")
    relay_ip = Column(String(50), nullable=True)
    notes = Column(Text, nullable=True)

    analysis = relationship("EmailAnalysis", back_populates="forensic_events")


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("email_analysis.id"), nullable=False)
    generated_at = Column(DateTime, default=datetime.datetime.utcnow)
    report_data = Column(JSON, nullable=False)

    analysis = relationship("EmailAnalysis", back_populates="reports")


def init_db():
    Base.metadata.create_all(bind=engine)
    # Automatic column migration for SQLite development fallback
    from sqlalchemy import text
    with engine.connect() as conn:
        for col_name, col_type in [
            ("auth_spf", "VARCHAR(50) DEFAULT 'unknown'"),
            ("auth_dkim", "VARCHAR(50) DEFAULT 'unknown'"),
            ("auth_dmarc", "VARCHAR(50) DEFAULT 'unknown'"),
            ("date_header", "VARCHAR(255)"),
            ("urls_data", "JSON"),
            ("attachments_data", "JSON"),
            ("timeline_data", "JSON"),
        ]:
            try:
                conn.execute(text(f"ALTER TABLE email_analysis ADD COLUMN {col_name} {col_type}"))
                conn.commit()
            except Exception:
                pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

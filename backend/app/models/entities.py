from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    Column, String, Boolean, Text, BigInteger, Numeric,
    Integer, ForeignKey, JSON, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship
from backend.app.core.database import Base, UTCDateTime

def utc_now():
    return datetime.now(timezone.utc)

def gen_uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    email = Column(String(320), unique=True, nullable=False, index=True)
    password_hash = Column(Text, nullable=False)
    full_name = Column(String(200), nullable=False)
    role = Column(String(32), nullable=False)  # ADMINISTRATOR, ANALYST, VIEWER
    is_active = Column(Boolean, default=True, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(UTCDateTime, nullable=True)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)
    updated_at = Column(UTCDateTime, default=utc_now, onupdate=utc_now, nullable=False)

    sessions = relationship("SessionModel", back_populates="user", cascade="all, delete-orphan")
    collected_evidence = relationship("Evidence", back_populates="collector")
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False, default="Browser Extension Key")
    prefix = Column(String(12), nullable=False)  # First few chars for identification
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)
    expires_at = Column(UTCDateTime, nullable=True)
    last_used_at = Column(UTCDateTime, nullable=True)

    user = relationship("User", back_populates="api_keys")


class JwtDenylist(Base):
    __tablename__ = "jwt_denylist"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    jti = Column(String(64), unique=True, nullable=False, index=True)
    revoked_at = Column(UTCDateTime, default=utc_now, nullable=False)
    expires_at = Column(UTCDateTime, nullable=False)


class SessionModel(Base):
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(Text, nullable=False)
    expires_at = Column(UTCDateTime, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)
    revoked_at = Column(UTCDateTime, nullable=True)

    user = relationship("User", back_populates="sessions")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    evidence_id = Column(String(32), unique=True, nullable=False, index=True)
    original_filename = Column(String(255), nullable=False)
    mime_type = Column(String(128), nullable=False)
    size_bytes = Column(BigInteger, nullable=False)
    sha256 = Column(String(64), nullable=False, unique=True, index=True)
    storage_path = Column(Text, nullable=False)
    source_type = Column(String(32), nullable=False, default="USER_UPLOAD")  # USER_UPLOAD, RAW_HEADER, EXTENSION_SCAN, IMAP
    collected_at = Column(UTCDateTime, default=utc_now, nullable=False)
    collected_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    retention_until = Column(UTCDateTime, nullable=True)
    legal_hold = Column(Boolean, default=False, nullable=False)
    chain_head_hmac = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    collector = relationship("User", back_populates="collected_evidence")
    email = relationship("Email", back_populates="evidence", uselist=False, cascade="all, delete-orphan")
    custody_events = relationship("CustodyEvent", back_populates="evidence", cascade="all, delete-orphan")
    cases = relationship("CaseEvidence", back_populates="evidence", cascade="all, delete-orphan")


class CustodyEvent(Base):
    __tablename__ = "custody_events"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    evidence_id = Column(String(36), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    action = Column(String(64), nullable=False)  # INGESTED, PARSED, ANALYZED, ANALYSIS_FAILED, EXPORTED, VIEWED, DECISION_RECORDED, DUPLICATE_SUBMISSION
    event_time = Column(UTCDateTime, default=utc_now, nullable=False)
    metadata_hash = Column(String(128), nullable=False)
    previous_event_hash = Column(String(128), nullable=True)
    event_hash = Column(String(128), nullable=False)
    details = Column(JSON, default=dict, nullable=False)

    evidence = relationship("Evidence", back_populates="custody_events")


class Email(Base):
    __tablename__ = "emails"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    evidence_id = Column(String(36), ForeignKey("evidence.id", ondelete="CASCADE"), unique=True, nullable=False)
    message_id = Column(Text, nullable=True, index=True)
    subject = Column(Text, nullable=True)
    from_name = Column(Text, nullable=True)
    from_address = Column(Text, nullable=True, index=True)
    from_domain = Column(Text, nullable=True, index=True)
    reply_to = Column(Text, nullable=True)
    return_path = Column(Text, nullable=True)
    sent_at = Column(UTCDateTime, nullable=True)
    received_at = Column(UTCDateTime, nullable=True)
    body_text = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    parser_status = Column(String(32), nullable=False, default="SUCCESS")
    parser_version = Column(String(32), nullable=False, default="1.0.0")
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    evidence = relationship("Evidence", back_populates="email")
    recipients = relationship("EmailRecipient", back_populates="email", cascade="all, delete-orphan")
    hops = relationship("ReceivedHop", back_populates="email", cascade="all, delete-orphan")
    auth_result = relationship("AuthenticationResult", back_populates="email", uselist=False, cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="email", cascade="all, delete-orphan")
    analysis_run = relationship("AnalysisRun", back_populates="email", uselist=False, cascade="all, delete-orphan")
    indicators = relationship("EmailIndicator", back_populates="email", cascade="all, delete-orphan")
    campaign_memberships = relationship("CampaignMember", back_populates="email", cascade="all, delete-orphan")


class EmailRecipient(Base):
    __tablename__ = "email_recipients"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    email_id = Column(String(36), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    address = Column(Text, nullable=False)
    recipient_type = Column(String(16), nullable=False)  # TO, CC, BCC

    email = relationship("Email", back_populates="recipients")


class ReceivedHop(Base):
    __tablename__ = "received_hops"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    email_id = Column(String(36), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    hop_order = Column(Integer, nullable=False)
    raw_value = Column(Text, nullable=False)
    hostname = Column(Text, nullable=True)
    ip_address = Column(String(64), nullable=True, index=True)
    timestamp = Column(UTCDateTime, nullable=True)
    trust_level = Column(String(32), nullable=False, default="OBSERVED_BY_TRUSTED_MTA")  # OBSERVED_BY_TRUSTED_MTA, CLAIMED, TRUSTED_GATEWAY
    trust_reason = Column(Text, nullable=True)
    geo_snapshot = Column(JSON, default=dict, nullable=False)

    email = relationship("Email", back_populates="hops")


class AuthenticationResult(Base):
    __tablename__ = "authentication_results"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    email_id = Column(String(36), ForeignKey("emails.id", ondelete="CASCADE"), unique=True, nullable=False)
    spf_result = Column(String(32), nullable=True)
    spf_alignment = Column(String(32), nullable=True)
    dkim_result = Column(String(32), nullable=True)
    dkim_alignment = Column(String(32), nullable=True)
    dmarc_result = Column(String(32), nullable=True)
    dmarc_alignment = Column(String(32), nullable=True)
    raw_header = Column(Text, nullable=True)
    source = Column(String(32), nullable=False, default="REPORTED")  # REPORTED vs VERIFIED
    verification_details = Column(JSON, default=dict, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    email = relationship("Email", back_populates="auth_result")


class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    email_id = Column(String(36), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(Text, nullable=False)
    content_type = Column(Text, nullable=True)
    size_bytes = Column(BigInteger, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    extension = Column(Text, nullable=True)
    static_risk = Column(String(16), nullable=False, default="UNKNOWN")
    metadata_json = Column(JSON, default=dict, nullable=False)

    email = relationship("Email", back_populates="attachments")


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    indicator_type = Column(String(32), nullable=False)  # EMAIL, DOMAIN, URL, IP, ASN, ATTACHMENT_HASH, MESSAGE_ID
    canonical_value = Column(Text, nullable=False)
    display_value = Column(Text, nullable=True)
    first_seen = Column(UTCDateTime, default=utc_now, nullable=False)
    last_seen = Column(UTCDateTime, default=utc_now, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("indicator_type", "canonical_value", name="uq_indicator_type_value"),
        Index("ix_indicator_type_value", "indicator_type", "canonical_value"),
    )

    enrichments = relationship("Enrichment", back_populates="indicator", cascade="all, delete-orphan")


class EmailIndicator(Base):
    __tablename__ = "email_indicators"

    email_id = Column(String(36), ForeignKey("emails.id", ondelete="CASCADE"), primary_key=True)
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True)
    source = Column(String(64), nullable=False)
    confidence = Column(Numeric(5, 4), nullable=True)

    email = relationship("Email", back_populates="indicators")
    indicator = relationship("Indicator")


class Enrichment(Base):
    __tablename__ = "enrichments"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False)  # KNOWN_MALICIOUS, KNOWN_BENIGN, UNKNOWN, UNAVAILABLE, ERROR
    result = Column(JSON, default=dict, nullable=False)
    confidence = Column(Numeric(5, 4), nullable=True)
    observed_at = Column(UTCDateTime, default=utc_now, nullable=False)
    expires_at = Column(UTCDateTime, nullable=True)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    indicator = relationship("Indicator", back_populates="enrichments")


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    email_id = Column(String(36), ForeignKey("emails.id", ondelete="CASCADE"), unique=True, nullable=False)
    engine_version = Column(String(32), nullable=False, default="2.0.0")
    status = Column(String(32), nullable=False, default="COMPLETED")  # RUNNING, COMPLETED, FAILED
    enrichment_status = Column(String(32), default="DONE", nullable=False)  # PENDING, RUNNING, DONE, PARTIAL, FAILED
    started_at = Column(UTCDateTime, default=utc_now, nullable=False)
    completed_at = Column(UTCDateTime, nullable=True)
    llm_used = Column(Boolean, default=False, nullable=False)
    external_intel_used = Column(Boolean, default=False, nullable=False)
    origin_assessment = Column(JSON, default=dict, nullable=False)
    error_message = Column(Text, nullable=True)

    email = relationship("Email", back_populates="analysis_run")
    findings = relationship("Finding", back_populates="analysis", cascade="all, delete-orphan")
    risk_score = relationship("RiskScore", back_populates="analysis", uselist=False, cascade="all, delete-orphan")
    llm_analysis = relationship("LLMAnalysis", back_populates="analysis", uselist=False, cascade="all, delete-orphan")
    phishdna = relationship("PhishDNA", back_populates="analysis", uselist=False, cascade="all, delete-orphan")
    recommended_actions = relationship("RecommendedAction", back_populates="analysis", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    category = Column(String(32), nullable=False)  # IDENTITY, AUTHENTICATION, DOMAIN_URL, INTENT, ATTACHMENT, INFRASTRUCTURE, INTEL
    code = Column(String(64), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL, INFO
    risk_contribution = Column(Numeric(6, 2), default=0.0, nullable=False)
    confidence = Column(Numeric(5, 4), nullable=True)
    provenance = Column(JSON, default=dict, nullable=False)
    evidence = Column(JSON, default=dict, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    analysis = relationship("AnalysisRun", back_populates="findings")


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), unique=True, nullable=False)
    score = Column(Numeric(5, 2), nullable=False, index=True)
    band = Column(String(16), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    verdict = Column(String(32), default="SUSPICIOUS", nullable=False, index=True)  # LEGITIMATE, SUSPICIOUS, IMPERSONATED, PHISHING, FRAUD
    confidence = Column(Numeric(5, 4), nullable=True)
    corroboration_level = Column(Numeric(5, 4), nullable=True)
    signal_snapshot = Column(JSON, default=dict, nullable=False)
    engine_version = Column(String(32), nullable=False, default="2.0.0")
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    analysis = relationship("AnalysisRun", back_populates="risk_score")


class LLMAnalysis(Base):
    __tablename__ = "llm_analyses"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), unique=True, nullable=False)
    provider = Column(String(64), nullable=False)
    model = Column(String(128), nullable=False)
    prompt_version = Column(String(32), nullable=False)
    intent_categories = Column(JSON, default=list, nullable=False)
    impersonation_target = Column(Text, nullable=True)
    urgency_level = Column(String(16), nullable=True)
    social_engineering_indicators = Column(JSON, default=list, nullable=False)
    semantic_risk = Column(Numeric(5, 2), nullable=True)
    confidence = Column(Numeric(5, 4), nullable=True)
    explanation = Column(JSON, default=list, nullable=False)
    status = Column(String(32), nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    analysis = relationship("AnalysisRun", back_populates="llm_analysis")


class PhishDNA(Base):
    __tablename__ = "phishdna"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), unique=True, nullable=False)
    fingerprint = Column(String(128), nullable=False, index=True)
    header_dna = Column(JSON, default=dict, nullable=False)
    identity_auth_dna = Column(JSON, default=dict, nullable=False)
    content_dna = Column(JSON, default=dict, nullable=False)
    url_dna = Column(JSON, default=dict, nullable=False)
    infrastructure_dna = Column(JSON, default=dict, nullable=False)
    behavioral_dna = Column(JSON, default=dict, nullable=False)
    attachment_dna = Column(JSON, default=dict, nullable=False)
    normalized_features = Column(JSON, default=dict, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    analysis = relationship("AnalysisRun", back_populates="phishdna")


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    campaign_key = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    confidence = Column(Numeric(5, 4), nullable=True)
    first_seen = Column(UTCDateTime, default=utc_now, nullable=False)
    last_seen = Column(UTCDateTime, default=utc_now, nullable=False)
    primary_intent = Column(String(64), nullable=True)
    state = Column(String(32), default="EMERGING", nullable=False)  # EMERGING, ACTIVE, EXPANDING, MONITORING
    risk_trend = Column(String(16), default="STABLE", nullable=False)  # INCREASING, STABLE, DECREASING
    status = Column(String(32), default="ACTIVE", nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    members = relationship("CampaignMember", back_populates="campaign", cascade="all, delete-orphan")
    snapshots = relationship("CampaignModelSnapshot", back_populates="campaign", cascade="all, delete-orphan")
    events = relationship("CampaignEvolutionEvent", back_populates="campaign", cascade="all, delete-orphan")


class CampaignMember(Base):
    __tablename__ = "campaign_members"

    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True)
    email_id = Column(String(36), ForeignKey("emails.id", ondelete="CASCADE"), primary_key=True)
    similarity_score = Column(Numeric(5, 2), nullable=True)
    relationship_reason = Column(JSON, default=list, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    campaign = relationship("Campaign", back_populates="members")
    email = relationship("Email", back_populates="campaign_memberships")


class CampaignModelSnapshot(Base):
    __tablename__ = "campaign_model_snapshots"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    state = Column(String(32), nullable=False)
    confidence = Column(Numeric(5, 4), nullable=True)
    risk_score = Column(Numeric(5, 2), nullable=True)
    risk_trend = Column(String(16), default="STABLE", nullable=False)
    dominant_intent = Column(String(64), nullable=True)
    message_count = Column(Integer, default=0, nullable=False)
    infrastructure_count = Column(Integer, default=0, nullable=False)
    evolution_event = Column(JSON, default=dict, nullable=False)
    triggered_by_analysis_id = Column(String(36), ForeignKey("analysis_runs.id"), nullable=True)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    campaign = relationship("Campaign", back_populates="snapshots")


class CampaignEvolutionEvent(Base):
    __tablename__ = "campaign_evolution_events"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    event_time = Column(UTCDateTime, default=utc_now, nullable=False)
    triggering_analysis_id = Column(String(36), ForeignKey("analysis_runs.id"), nullable=True)
    triggering_evidence_id = Column(String(36), ForeignKey("evidence.id"), nullable=True)
    summary = Column(Text, nullable=False)
    previous_value = Column(JSON, nullable=True)
    new_value = Column(JSON, nullable=True)
    confidence = Column(Numeric(5, 4), nullable=True)
    provenance = Column(JSON, default=dict, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    campaign = relationship("Campaign", back_populates="events")


class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    node_type = Column(String(32), nullable=False)  # EMAIL, SENDER, RECIPIENT, DOMAIN, URL, IP, ASN, ATTACHMENT_HASH, CAMPAIGN, INTENT, REGISTRAR, SUBNET
    reference_id = Column(String(36), nullable=True, index=True)
    label = Column(Text, nullable=False)
    value = Column(Text, nullable=True)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    from_node = Column(String(36), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    to_node = Column(String(36), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    relation = Column(String(64), nullable=False)
    confidence = Column(Numeric(5, 4), nullable=True)
    source = Column(String(64), nullable=False)
    evidence = Column(JSON, default=dict, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)


class Case(Base):
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    case_key = Column(String(32), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(16), nullable=False)
    status = Column(String(32), default="OPEN", nullable=False, index=True)  # OPEN, INVESTIGATING, CONTAINED, CLOSED
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    summary = Column(Text, nullable=True)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)
    updated_at = Column(UTCDateTime, default=utc_now, onupdate=utc_now, nullable=False)
    closed_at = Column(UTCDateTime, nullable=True)

    evidences = relationship("CaseEvidence", back_populates="case", cascade="all, delete-orphan")
    decisions = relationship("AnalystDecision", back_populates="case", cascade="all, delete-orphan")
    owner = relationship("User", foreign_keys=[owner_id])
    creator = relationship("User", foreign_keys=[created_by])


class CaseEvidence(Base):
    __tablename__ = "case_evidence"

    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True)
    evidence_id = Column(String(36), ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True)
    added_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    added_at = Column(UTCDateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="evidences")
    evidence = relationship("Evidence", back_populates="cases")


class AnalystDecision(Base):
    __tablename__ = "analyst_decisions"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    analyst_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    decision = Column(String(32), nullable=False)
    comment = Column(Text, nullable=True)
    score_at_decision = Column(Numeric(5, 2), nullable=True)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="decisions")
    analyst = relationship("User")


class RecommendedAction(Base):
    __tablename__ = "recommended_actions"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    priority = Column(String(16), nullable=False)
    action_code = Column(String(64), nullable=False)
    title = Column(String(255), nullable=False)
    explanation = Column(Text, nullable=False)
    evidence_refs = Column(JSON, default=list, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    analysis = relationship("AnalysisRun", back_populates="recommended_actions")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    actor_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    action = Column(String(128), nullable=False)
    object_type = Column(String(64), nullable=False)
    object_id = Column(String(36), nullable=True)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False, index=True)


class ThreatIntelEntry(Base):
    __tablename__ = "threat_intel_entries"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    indicator_type = Column(String(32), nullable=False)
    canonical_value = Column(Text, nullable=False)
    verdict = Column(String(32), nullable=False)
    source = Column(String(64), nullable=False)
    confidence = Column(Numeric(5, 4), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("indicator_type", "canonical_value", "source", name="uq_intel_indicator_source"),
    )


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(String(100), nullable=False)
    trigger_type = Column(String(32), nullable=False)  # VERDICT_THRESHOLD, RISK_SCORE_THRESHOLD, CAMPAIGN_STATE_CHANGE, INTEL_HIT
    conditions = Column(JSON, default=dict, nullable=False)
    channels = Column(JSON, default=list, nullable=False)  # ["IN_APP", "WEBHOOK", "EMAIL"]
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False)


class AlertNotification(Base):
    __tablename__ = "alert_notifications"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    rule_id = Column(String(36), ForeignKey("alert_rules.id", ondelete="SET NULL"), nullable=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(16), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    message = Column(Text, nullable=False)
    target_object_type = Column(String(32), nullable=False)  # EMAIL, CAMPAIGN, CASE
    target_object_id = Column(String(36), nullable=False)
    is_acknowledged = Column(Boolean, default=False, nullable=False)
    acknowledged_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(UTCDateTime, default=utc_now, nullable=False, index=True)

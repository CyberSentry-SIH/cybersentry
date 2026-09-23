from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, ConfigDict, EmailStr, Field

# ----------------- User & Auth Schemas -----------------
class UserBase(BaseModel):
    email: str
    full_name: str
    role: str

class UserCreateRequest(UserBase):
    password: str

class UserResponse(UserBase):
    id: str
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class LoginRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# ----------------- Evidence & Custody Schemas -----------------
class CustodyEventResponse(BaseModel):
    id: str
    action: str
    event_time: datetime
    metadata_hash: str
    previous_event_hash: Optional[str] = None
    event_hash: str
    details: Dict[str, Any]
    model_config = ConfigDict(from_attributes=True)

class EvidenceResponse(BaseModel):
    id: str
    evidence_id: str
    original_filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    source_type: str
    collected_at: datetime
    custody_events: List[CustodyEventResponse] = []
    model_config = ConfigDict(from_attributes=True)

# ----------------- Email Details Schemas -----------------
class ReceivedHopResponse(BaseModel):
    id: str
    hop_order: int
    raw_value: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: Optional[datetime] = None
    trust_level: str
    trust_reason: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class AuthResultResponse(BaseModel):
    spf_result: Optional[str] = None
    spf_alignment: Optional[str] = None
    dkim_result: Optional[str] = None
    dkim_alignment: Optional[str] = None
    dmarc_result: Optional[str] = None
    dmarc_alignment: Optional[str] = None
    raw_header: Optional[str] = None
    source: str
    model_config = ConfigDict(from_attributes=True)

class AttachmentResponse(BaseModel):
    id: str
    filename: str
    content_type: Optional[str] = None
    size_bytes: int
    sha256: str
    extension: Optional[str] = None
    static_risk: str
    metadata_json: Dict[str, Any] = {}
    model_config = ConfigDict(from_attributes=True)

class EmailDetailResponse(BaseModel):
    id: str
    evidence_id: str
    message_id: Optional[str] = None
    subject: Optional[str] = None
    from_name: Optional[str] = None
    from_address: Optional[str] = None
    from_domain: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    sent_at: Optional[datetime] = None
    received_at: Optional[datetime] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    parser_status: str
    hops: List[ReceivedHopResponse] = []
    auth_result: Optional[AuthResultResponse] = None
    attachments: List[AttachmentResponse] = []
    model_config = ConfigDict(from_attributes=True)

# ----------------- Finding & Risk Schemas -----------------
class FindingResponse(BaseModel):
    id: str
    category: str
    code: str
    title: str
    description: str
    severity: str
    risk_contribution: float
    confidence: Optional[float] = None
    provenance: Dict[str, Any] = {}
    evidence: Dict[str, Any] = {}
    model_config = ConfigDict(from_attributes=True)

class RiskScoreResponse(BaseModel):
    score: float
    band: str
    confidence: Optional[float] = None
    signal_snapshot: Dict[str, Any] = {}
    engine_version: str
    model_config = ConfigDict(from_attributes=True)

class PhishDNAResponse(BaseModel):
    fingerprint: str
    header_dna: Dict[str, Any] = {}
    identity_auth_dna: Dict[str, Any] = {}
    content_dna: Dict[str, Any] = {}
    url_dna: Dict[str, Any] = {}
    infrastructure_dna: Dict[str, Any] = {}
    behavioral_dna: Dict[str, Any] = {}
    attachment_dna: Dict[str, Any] = {}
    normalized_features: Dict[str, Any] = {}
    model_config = ConfigDict(from_attributes=True)

class RecommendedActionResponse(BaseModel):
    id: str
    priority: str
    action_code: str
    title: str
    explanation: str
    evidence_refs: List[Any] = []
    model_config = ConfigDict(from_attributes=True)

class LLMAnalysisResponse(BaseModel):
    provider: str
    model: str
    intent_categories: List[str] = []
    impersonation_target: Optional[str] = None
    urgency_level: Optional[str] = None
    social_engineering_indicators: List[str] = []
    semantic_risk: Optional[float] = None
    confidence: Optional[float] = None
    explanation: List[str] = []
    status: str
    model_config = ConfigDict(from_attributes=True)

class AnalysisDetailResponse(BaseModel):
    id: str
    email_id: str
    evidence_id: str
    status: str
    engine_version: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    llm_used: bool
    external_intel_used: bool
    risk_score: Optional[RiskScoreResponse] = None
    phishdna: Optional[PhishDNAResponse] = None
    findings: List[FindingResponse] = []
    recommended_actions: List[RecommendedActionResponse] = []
    llm_analysis: Optional[LLMAnalysisResponse] = None
    email: Optional[EmailDetailResponse] = None
    model_config = ConfigDict(from_attributes=True)

# ----------------- Campaign Schemas -----------------
class CampaignEvolutionEventResponse(BaseModel):
    id: str
    campaign_id: str
    event_type: str
    event_time: datetime
    summary: str
    previous_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    confidence: Optional[float] = None
    provenance: Dict[str, Any] = {}
    model_config = ConfigDict(from_attributes=True)

class CampaignResponse(BaseModel):
    id: str
    campaign_key: str
    name: str
    confidence: Optional[float] = None  # internal heuristic weight, not a calibrated probability
    relationship_strength: Optional[str] = None  # e.g. "86/100 (HIGH)" -- what the UI should display
    first_seen: datetime
    last_seen: datetime
    primary_intent: Optional[str] = None
    state: str
    risk_trend: str
    status: str
    member_count: int = 0
    members: List[Dict[str, Any]] = []
    events: List[CampaignEvolutionEventResponse] = []
    model_config = ConfigDict(from_attributes=True)

class WhatChangedResponse(BaseModel):
    email_a: Dict[str, Any]
    email_b: Dict[str, Any]
    similarity_score: float
    campaign_relationship: Optional[str] = None
    relationship_strength: Optional[str] = None
    differences: Dict[str, Any]
    shared_indicators: List[Dict[str, Any]]
    phishdna_comparison: Dict[str, Any]
    mutated_surface_features: List[Dict[str, Any]] = []
    retained_attack_invariants: List[Dict[str, Any]] = []
    infrastructure_relationships: List[Dict[str, Any]] = []

# ----------------- Graph Schemas -----------------
class GraphNodeResponse(BaseModel):
    id: str
    node_type: str
    reference_id: Optional[str] = None
    label: str
    value: Optional[str] = None
    metadata_json: Dict[str, Any] = {}

class GraphEdgeResponse(BaseModel):
    id: str
    from_node: str
    to_node: str
    relation: str
    confidence: Optional[float] = None  # internal heuristic weight, not a calibrated probability
    evidence_strength: Optional[str] = None  # e.g. "STRONG" -- what the UI should display
    source: str
    evidence: Dict[str, Any] = {}

class AttackIntentGraphResponse(BaseModel):
    nodes: List[GraphNodeResponse]
    edges: List[GraphEdgeResponse]

# ----------------- Case & Decision Schemas -----------------
class CaseCreateRequest(BaseModel):
    title: str
    severity: str
    summary: Optional[str] = None
    evidence_ids: List[str] = []

class CaseUpdateRequest(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    summary: Optional[str] = None

class AnalystDecisionRequest(BaseModel):
    decision: str  # CONFIRMED_PHISHING, FALSE_POSITIVE, NEEDS_INVESTIGATION
    comment: Optional[str] = None

class AnalystDecisionResponse(BaseModel):
    id: str
    case_id: str
    analyst_name: str
    decision: str
    comment: Optional[str] = None
    score_at_decision: Optional[float] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class CaseResponse(BaseModel):
    id: str
    case_key: str
    title: str
    severity: str
    status: str
    owner_name: Optional[str] = None
    created_by_name: str
    summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    evidence_count: int = 0
    decisions: List[AnalystDecisionResponse] = []
    model_config = ConfigDict(from_attributes=True)

# ----------------- Dashboard & Stats -----------------
class DashboardStatsResponse(BaseModel):
    total_analyzed: int
    critical_findings: int
    high_findings: int
    open_cases: int
    active_campaigns: int
    recent_analyses: List[Dict[str, Any]]

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: 'ANALYST' | 'ADMINISTRATOR';
  is_active: boolean;
  created_at: string;
}

export interface CustodyEvent {
  id: string;
  action: string;
  event_time: string;
  metadata_hash: string;
  previous_event_hash: string | null;
  event_hash: string;
  details: Record<string, any>;
}

export interface Evidence {
  id: string;
  evidence_id: string;
  original_filename: string;
  mime_type: string;
  size_bytes: number;
  sha256: string;
  source_type: string;
  collected_at: string;
  custody_events?: CustodyEvent[];
}

export interface ReceivedHop {
  id: string;
  hop_order: number;
  raw_value: string;
  hostname?: string;
  ip_address?: string;
  trust_level: 'TRUSTED' | 'OBSERVED' | 'UNTRUSTED' | 'UNKNOWN';
  trust_reason?: string;
}

export interface AuthResult {
  spf_result?: string;
  dkim_result?: string;
  dmarc_result?: string;
  raw_header?: string;
  source: string;
}

export interface Attachment {
  id: string;
  filename: string;
  content_type?: string;
  size_bytes: number;
  sha256: string;
  extension?: string;
  static_risk: string;
  metadata_json: Record<string, any>;
}

export interface EmailDetail {
  id: string;
  evidence_id: string;
  message_id?: string;
  subject?: string;
  from_name?: string;
  from_address?: string;
  from_domain?: string;
  reply_to?: string;
  return_path?: string;
  sent_at?: string;
  received_at?: string;
  body_text?: string;
  body_html?: string;
  parser_status: string;
  hops: ReceivedHop[];
  auth_result?: AuthResult;
  attachments: Attachment[];
}

export interface Finding {
  id: string;
  category: string;
  code: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INFO';
  risk_contribution: number;
  confidence?: number;
  provenance: Record<string, any>;
  evidence: Record<string, any>;
}

export interface RiskScore {
  score: number;
  band: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence?: number;
  signal_snapshot: Record<string, any>;
  engine_version: string;
}

export interface PhishDNA {
  fingerprint: string;
  header_dna: Record<string, any>;
  identity_auth_dna: Record<string, any>;
  content_dna: Record<string, any>;
  url_dna: Record<string, any>;
  infrastructure_dna: Record<string, any>;
  behavioral_dna: Record<string, any>;
  attachment_dna: Record<string, any>;
  normalized_features: Record<string, any>;
}

export interface RecommendedAction {
  id: string;
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  action_code: string;
  title: string;
  explanation: string;
  evidence_refs: any[];
}

export interface LLMAnalysis {
  provider: string;
  model: string;
  intent_categories: string[];
  impersonation_target?: string;
  urgency_level?: string;
  social_engineering_indicators: string[];
  semantic_risk?: number;
  confidence?: number;
  explanation: string[];
  status: string;
}

export interface AnalysisDetail {
  id: string;
  email_id: string;
  evidence_id: string;
  status: string;
  engine_version: string;
  started_at: string;
  completed_at?: string;
  llm_used: boolean;
  external_intel_used: boolean;
  risk_score?: RiskScore;
  phishdna?: PhishDNA;
  findings: Finding[];
  recommended_actions: RecommendedAction[];
  llm_analysis?: LLMAnalysis;
  email?: EmailDetail;
}

export interface CampaignEvolutionEvent {
  id: string;
  campaign_id: string;
  event_type: string;
  event_time: string;
  summary: string;
  confidence?: number;
}

export interface Campaign {
  id: string;
  campaign_key: string;
  name: string;
  confidence?: number; // internal heuristic weight, not a calibrated probability -- display relationship_strength instead
  relationship_strength?: string; // e.g. "86/100 (HIGH)"
  first_seen: string;
  last_seen: string;
  primary_intent?: string;
  state: 'CANDIDATE' | 'EMERGING' | 'ACTIVE' | 'EXPANDING' | 'MONITORING';
  risk_trend: 'INCREASING' | 'STABLE' | 'DECREASING';
  status: string;
  member_count: number;
  members: any[];
  events: CampaignEvolutionEvent[];
}

export interface CampaignInvestigation {
  campaign_id: string;
  campaign_key: string;
  name: string;
  state: string;
  risk_trend: string;
  relationship_strength?: string;
  member_count: number;
  related_emails: Array<{
    email_id: string;
    evidence_id?: string;
    subject?: string;
    from_address?: string;
    sent_at?: string;
    relationship_reason: string[];
  }>;
  attack_invariants: Array<{
    invariant: string;
    retained: boolean;
    value: string;
    category?: string;
  }>;
  infrastructure_relationships: Array<{
    relationship_type: string;
    matched: boolean;
    evidence: string;
    strength: string;
  }>;
  variance_timeline: Array<{
    from_email_id: string;
    from_evidence_id?: string;
    to_email_id: string;
    to_evidence_id?: string;
    similarity_score?: number;
    relationship_strength?: string;
    mutated_surface_features: Array<{
      feature: string;
      changed: boolean;
      variant_a: string;
      variant_b: string;
      interpretation: string;
    }>;
    differences: Record<string, any>;
  }>;
  indicators: {
    sender_domains: string[];
    sender_addresses: string[];
    infrastructure_ips: string[];
    url_linked_domains: string[];
    phishdna_fingerprints: string[];
    attachment_hashes: string[];
  };
  campaign_timeline: Array<{
    event_type: string;
    event_time: string;
    summary: string;
  }>;
  evidence_refs: string[];
}

export interface GraphNode {
  id: string;
  node_type: string;
  reference_id?: string;
  label: string;
  value?: string;
  metadata_json: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  from_node: string;
  to_node: string;
  relation: string;
  confidence?: number; // internal heuristic weight, not a calibrated probability -- display evidence_strength instead
  evidence_strength?: string; // e.g. "STRONG"
  source: string;
  evidence: Record<string, any>;
}

export interface AttackIntentGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Case {
  id: string;
  case_key: string;
  title: string;
  severity: string;
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'CLOSED';
  owner_name?: string;
  created_by_name: string;
  summary?: string;
  created_at: string;
  updated_at: string;
  evidence_count: number;
  decisions: any[];
}

export interface DashboardStats {
  total_analyzed: number;
  critical_findings: number;
  high_findings: number;
  open_cases: number;
  active_campaigns: number;
  recent_analyses: Array<{
    id: string;
    email_id: string;
    evidence_id: string;
    subject: string;
    sender: string;
    risk_score: number;
    risk_band: string;
    campaign: string | null;
    intent: string;
    analyzed_at: string;
  }>;
}

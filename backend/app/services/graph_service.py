import uuid
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from backend.app.models import (
    GraphNode, GraphEdge, Email, Evidence, AnalysisRun
)

def build_attack_graph_for_email(
    db: Session,
    email_id: str,
    subject: str,
    from_address: str,
    from_domain: str,
    recipients: List[str],
    urls: List[str],
    hops: List[Dict[str, Any]],
    attachments: List[Dict[str, Any]],
    intent: str,
    campaign_key: Optional[str] = None
) -> Dict[str, Any]:
    nodes = []
    edges = []

    # 1. Email Node
    email_node = get_or_create_node(
        db, node_type="EMAIL", reference_id=email_id,
        label=subject[:40] if subject else "Suspicious Email",
        value=email_id,
        metadata={"subject": subject}
    )
    nodes.append(email_node)

    # 2. Sender Node
    sender_node = None
    if from_address:
        sender_node = get_or_create_node(
            db, node_type="SENDER", reference_id=None,
            label=from_address,
            value=from_address
        )
        nodes.append(sender_node)
        edges.append(create_edge(
            db, email_node.id, sender_node.id, "SENT_BY", "PARSED_HEADER",
            confidence=0.95,
            evidence={"reason": "RFC 5322 From header", "address": from_address}
        ))

    # 3. Domain Node
    if from_domain:
        domain_node = get_or_create_node(
            db, node_type="DOMAIN", reference_id=None,
            label=from_domain,
            value=from_domain
        )
        nodes.append(domain_node)
        if sender_node:
            edges.append(create_edge(
                db, sender_node.id, domain_node.id, "RESOLVES_TO", "DNS_RESOLUTION",
                confidence=0.92,
                evidence={"reason": "Sender mailbox domain resolution", "domain": from_domain}
            ))

    # 4. Recipient Nodes
    for rec in recipients:
        if not rec:
            continue
        rec_node = get_or_create_node(
            db, node_type="RECIPIENT", reference_id=None,
            label=rec,
            value=rec
        )
        nodes.append(rec_node)
        edges.append(create_edge(
            db, email_node.id, rec_node.id, "TARGETS", "DELIVERY_HEADER",
            confidence=0.95,
            evidence={"reason": "RFC 5322 To/Cc recipient address", "recipient": rec}
        ))

    # 5. URL Nodes and Target Domain Linkage
    for u in urls:
        if not u:
            continue
        try:
            parsed_u = urlparse(u)
            host = (parsed_u.hostname or u)[:35]
        except Exception:
            host = u[:35]

        url_node = get_or_create_node(
            db, node_type="URL", reference_id=None,
            label=host or u[:30],
            value=u
        )
        nodes.append(url_node)
        edges.append(create_edge(
            db, email_node.id, url_node.id, "CONTAINS_URL", "CONTENT_PARSER",
            confidence=0.90,
            evidence={"reason": "HTML anchor / plaintext URL extracted from body", "url": u}
        ))

        if host and host != from_domain:
            url_domain_node = get_or_create_node(
                db, node_type="DOMAIN", reference_id=None,
                label=host,
                value=host
            )
            nodes.append(url_domain_node)
            edges.append(create_edge(
                db, url_node.id, url_domain_node.id, "HOSTED_ON", "URL_PARSER",
                confidence=0.92,
                evidence={"reason": "Target hostname domain extraction", "domain": host}
            ))

    # 6. IP & Sending Infrastructure Nodes
    for h in hops:
        ip = h.get("ip_address")
        if ip:
            trust_level = h.get("trust_level", "OBSERVED")
            ip_node = get_or_create_node(
                db, node_type="IP", reference_id=None,
                label=ip,
                value=ip,
                metadata={"trust_level": trust_level, "trust_reason": h.get("trust_reason", "")}
            )
            nodes.append(ip_node)
            edges.append(create_edge(
                db, email_node.id, ip_node.id, "ROUTED_VIA", "RECEIVED_HEADER",
                confidence=0.85 if trust_level == "OBSERVED" else 0.95,
                evidence={
                    "reason": f"Observed in Received MTA hop ({trust_level})",
                    "ip": ip,
                    "trust_level": trust_level,
                    "trust_reason": h.get("trust_reason", "")
                }
            ))

    # 7. Attachment Nodes
    for att in (attachments or []):
        filename = att.get("filename") or "Attachment"
        sha256 = att.get("sha256") or ""
        att_node = get_or_create_node(
            db, node_type="ATTACHMENT", reference_id=None,
            label=filename[:30],
            value=sha256 or filename,
            metadata={"file_type": att.get("file_type", ""), "sha256": sha256}
        )
        nodes.append(att_node)
        edges.append(create_edge(
            db, email_node.id, att_node.id, "HAS_ATTACHMENT", "MIME_PARSER",
            confidence=0.95,
            evidence={"reason": "MIME multipart payload attachment", "filename": filename, "sha256": sha256}
        ))

    # 8. Intent Node
    if intent:
        intent_node = get_or_create_node(
            db, node_type="INTENT", reference_id=None,
            label=intent.replace("_", " ").title(),
            value=intent
        )
        nodes.append(intent_node)
        edges.append(create_edge(
            db, email_node.id, intent_node.id, "HAS_INTENT", "SEMANTIC_CLASSIFIER",
            confidence=0.88,
            evidence={"reason": "Semantic NLP & heuristic pattern matching", "intent": intent}
        ))

    # 9. Campaign Node
    if campaign_key:
        camp_node = get_or_create_node(
            db, node_type="CAMPAIGN", reference_id=None,
            label=campaign_key,
            value=campaign_key
        )
        nodes.append(camp_node)
        edges.append(create_edge(
            db, email_node.id, camp_node.id, "PART_OF_CAMPAIGN", "PHISHDNA_CORRELATION",
            confidence=0.89,
            evidence={"reason": "PhishDNA multi-family structural & infrastructure correlation", "campaign_key": campaign_key}
        ))

    return {
        "nodes": [format_node(n) for n in nodes],
        "edges": [format_edge(e) for e in edges]
    }

def get_or_create_node(
    db: Session,
    node_type: str,
    reference_id: Optional[str],
    label: str,
    value: Optional[str],
    metadata: Optional[dict] = None
) -> GraphNode:
    if metadata is None:
        metadata = {}

    if node_type == "EMAIL":
        existing = (
            db.query(GraphNode)
            .filter(
                GraphNode.node_type == "EMAIL",
                (GraphNode.reference_id == reference_id) | (GraphNode.value == value)
            )
            .first()
        )
    else:
        existing = (
            db.query(GraphNode)
            .filter(GraphNode.node_type == node_type, GraphNode.label == label)
            .first()
        )
    if existing:
        if metadata and not existing.metadata_json:
            existing.metadata_json = metadata
        return existing

    new_node = GraphNode(
        node_type=node_type,
        reference_id=reference_id,
        label=label,
        value=value,
        metadata_json=metadata
    )
    db.add(new_node)
    db.flush()
    return new_node

def create_edge(
    db: Session,
    from_node_id: str,
    to_node_id: str,
    relation: str,
    source: str,
    confidence: float = 0.90,
    evidence: Optional[Dict[str, Any]] = None
) -> GraphEdge:
    if evidence is None:
        evidence = {}

    existing = (
        db.query(GraphEdge)
        .filter(
            GraphEdge.from_node == from_node_id,
            GraphEdge.to_node == to_node_id,
            GraphEdge.relation == relation
        )
        .first()
    )
    if existing:
        existing.evidence = evidence
        existing.confidence = confidence
        return existing

    new_edge = GraphEdge(
        from_node=from_node_id,
        to_node=to_node_id,
        relation=relation,
        source=source,
        confidence=confidence,
        evidence=evidence
    )
    db.add(new_edge)
    db.flush()
    return new_edge

def ensure_attack_graph_for_email(db: Session, identifier: str) -> str:
    """
    Ensure an attack graph exists for the given email/evidence/analysis identifier.
    If graph nodes are missing or empty, constructs and persists the graph on the fly.
    Returns the resolved email_id string.
    """
    if not identifier:
        return ""

    email_obj = (
        db.query(Email)
        .filter((Email.id == identifier) | (Email.evidence_id == identifier))
        .first()
    )
    if not email_obj:
        ev = (
            db.query(Evidence)
            .filter((Evidence.id == identifier) | (Evidence.evidence_id == identifier))
            .first()
        )
        if ev and ev.email:
            email_obj = ev.email
    if not email_obj:
        ar = (
            db.query(AnalysisRun)
            .filter((AnalysisRun.id == identifier) | (AnalysisRun.email_id == identifier))
            .first()
        )
        if ar and ar.email:
            email_obj = ar.email

    if not email_obj:
        return identifier

    email_id = email_obj.id

    # Check if EMAIL node exists for this email
    existing_node = (
        db.query(GraphNode)
        .filter(
            GraphNode.node_type == "EMAIL",
            (GraphNode.reference_id == email_id) | (GraphNode.value == email_id)
        )
        .first()
    )

    # Check if there are edges connected to it
    has_edges = False
    if existing_node:
        has_edges = db.query(GraphEdge).filter(
            (GraphEdge.from_node == existing_node.id) | (GraphEdge.to_node == existing_node.id)
        ).first() is not None

    if not existing_node or not has_edges:
        # Build attack graph from email relations
        recipients = [r.address for r in email_obj.recipients] if email_obj.recipients else []
        urls = [
            ind.indicator_value
            for ind in email_obj.indicators
            if ind.indicator_type in ("URL", "DOMAIN")
        ] if email_obj.indicators else []

        hops_data = []
        if email_obj.hops:
            for h in email_obj.hops:
                if h.ip_address:
                    hops_data.append({
                        "ip_address": h.ip_address,
                        "trust_level": getattr(h, "trust_level", "OBSERVED") or "OBSERVED",
                        "trust_reason": getattr(h, "trust_reason", "") or ""
                    })

        attachments_data = []
        if email_obj.attachments:
            for a in email_obj.attachments:
                attachments_data.append({
                    "filename": a.filename,
                    "file_type": a.file_type,
                    "sha256": a.sha256
                })

        intent = "SUSPICIOUS_PHISHING"
        campaign_key = None
        if email_obj.analysis_run:
            ar = email_obj.analysis_run
            if ar.phishdna:
                pdna = ar.phishdna
                if hasattr(pdna, "campaign_key") and pdna.campaign_key:
                    campaign_key = pdna.campaign_key
                elif isinstance(pdna, dict) and pdna.get("campaign_key"):
                    campaign_key = pdna.get("campaign_key")
                
                if hasattr(pdna, "structural_dna") and isinstance(pdna.structural_dna, dict):
                    intent = pdna.structural_dna.get("intent", intent)

            if ar.risk_score:
                rs = ar.risk_score
                if hasattr(rs, "band") and rs.band:
                    intent = f"{rs.band}_RISK"
                elif isinstance(rs, dict) and rs.get("band"):
                    intent = f"{rs.get('band')}_RISK"

        build_attack_graph_for_email(
            db=db,
            email_id=email_id,
            subject=email_obj.subject or "Suspicious Email",
            from_address=email_obj.from_address or "",
            from_domain=email_obj.from_domain or "",
            recipients=recipients,
            urls=urls,
            hops=hops_data,
            attachments=attachments_data,
            intent=intent,
            campaign_key=campaign_key
        )
        try:
            db.commit()
        except Exception:
            db.rollback()

    return email_id

def format_node(node: GraphNode) -> Dict[str, Any]:
    return {
        "id": node.id,
        "node_type": node.node_type,
        "reference_id": node.reference_id,
        "label": node.label,
        "value": node.value,
        "metadata_json": node.metadata_json or {}
    }

def format_edge(edge: GraphEdge) -> Dict[str, Any]:
    conf = float(edge.confidence or 0.85)
    evidence_tier = "STRONG" if conf >= 0.90 else ("MODERATE" if conf >= 0.75 else "BASELINE")
    return {
        "id": edge.id,
        "from_node": edge.from_node,
        "to_node": edge.to_node,
        "relation": edge.relation,
        "confidence": conf,
        "evidence_strength": evidence_tier,
        "source": edge.source,
        "evidence": edge.evidence or {}
    }


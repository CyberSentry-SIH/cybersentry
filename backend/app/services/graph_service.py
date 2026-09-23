import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.app.models import GraphNode, GraphEdge

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
        label=subject[:30] or "Suspicious Email",
        value=email_id,
        metadata={"subject": subject}
    )
    nodes.append(email_node)

    # 2. Sender Node
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
        if from_address:
            edges.append(create_edge(
                db, sender_node.id, domain_node.id, "RESOLVES_TO", "DNS_RESOLUTION",
                confidence=0.92,
                evidence={"reason": "Sender mailbox domain resolution", "domain": from_domain}
            ))

    # 4. Recipient Nodes
    for rec in recipients:
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

    # 5. URL Nodes
    for u in urls:
        from urllib.parse import urlparse
        host = (urlparse(u).hostname or u)[:30]
        url_node = get_or_create_node(
            db, node_type="URL", reference_id=None,
            label=host,
            value=u
        )
        nodes.append(url_node)
        edges.append(create_edge(
            db, email_node.id, url_node.id, "CONTAINS_URL", "CONTENT_PARSER",
            confidence=0.90,
            evidence={"reason": "HTML anchor / plaintext URL extracted from body", "url": u}
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

    # 7. Intent Node
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

    # 8. Campaign Node
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

    existing = (
        db.query(GraphNode)
        .filter(GraphNode.node_type == node_type, GraphNode.label == label)
        .first()
    )
    if existing:
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

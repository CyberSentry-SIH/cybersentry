from typing import Optional, Set
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models import GraphNode, GraphEdge, User
from backend.app.schemas import AttackIntentGraphResponse, GraphNodeResponse, GraphEdgeResponse
from backend.app.api.deps import get_current_user
from backend.app.core.strength import evidence_strength_label
from backend.app.services.graph_service import ensure_attack_graph_for_email

router = APIRouter(prefix="/graph", tags=["Attack Intent Graph"])

@router.get("/", response_model=AttackIntentGraphResponse)
def get_graph(
    email_id: Optional[str] = Query(None, description="Filter graph for specific email"),
    limit: int = Query(100, description="Max nodes to fetch"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if email_id:
        # 1. Ensure attack graph exists and resolve true email_id
        resolved_email_id = ensure_attack_graph_for_email(db, email_id)

        # 2. Find the root email node
        email_node = db.query(GraphNode).filter(
            (GraphNode.node_type == "EMAIL") &
            ((GraphNode.reference_id == resolved_email_id) | (GraphNode.value == resolved_email_id))
        ).first()

        if not email_node:
            email_node = db.query(GraphNode).filter(
                (GraphNode.reference_id == resolved_email_id) | (GraphNode.value == resolved_email_id)
            ).first()

        if email_node:
            # Multi-hop connected subgraph traversal
            active_node_ids: Set[str] = {email_node.id}
            collected_edge_map = {}

            # Hop 1: Direct edges from/to email node
            hop1_edges = db.query(GraphEdge).filter(
                (GraphEdge.from_node == email_node.id) | (GraphEdge.to_node == email_node.id)
            ).all()

            for e in hop1_edges:
                collected_edge_map[e.id] = e
                active_node_ids.add(e.from_node)
                active_node_ids.add(e.to_node)

            # Hop 2: Secondary edges between connected entities (e.g. SENDER -> DOMAIN, URL -> DOMAIN)
            if active_node_ids:
                hop2_edges = db.query(GraphEdge).filter(
                    (GraphEdge.from_node.in_(active_node_ids)) | (GraphEdge.to_node.in_(active_node_ids))
                ).all()

                for e in hop2_edges:
                    collected_edge_map[e.id] = e
                    active_node_ids.add(e.from_node)
                    active_node_ids.add(e.to_node)

            final_edges = list(collected_edge_map.values())
            final_nodes = db.query(GraphNode).filter(GraphNode.id.in_(active_node_ids)).all()
        else:
            final_nodes = []
            final_edges = []
    else:
        # SOC overview graph (unfiltered)
        nodes = db.query(GraphNode).limit(limit).all()
        node_ids = {n.id for n in nodes}

        if node_ids:
            edges = db.query(GraphEdge).filter(
                (GraphEdge.from_node.in_(node_ids)) | (GraphEdge.to_node.in_(node_ids))
            ).limit(limit * 2).all()

            missing_node_ids = set()
            for e in edges:
                if e.from_node not in node_ids:
                    missing_node_ids.add(e.from_node)
                if e.to_node not in node_ids:
                    missing_node_ids.add(e.to_node)

            if missing_node_ids:
                extra_nodes = db.query(GraphNode).filter(GraphNode.id.in_(missing_node_ids)).all()
                nodes.extend(extra_nodes)
            final_nodes = nodes
            final_edges = edges
        else:
            final_nodes = []
            final_edges = []

    return AttackIntentGraphResponse(
        nodes=[
            GraphNodeResponse(
                id=n.id,
                node_type=n.node_type,
                reference_id=n.reference_id,
                label=n.label,
                value=n.value,
                metadata_json=n.metadata_json or {}
            )
            for n in final_nodes
        ],
        edges=[
            GraphEdgeResponse(
                id=e.id,
                from_node=e.from_node,
                to_node=e.to_node,
                relation=e.relation,
                confidence=float(e.confidence or 0.9),
                evidence_strength=evidence_strength_label(float(e.confidence or 0.9)),
                source=e.source,
                evidence=e.evidence or {}
            )
            for e in final_edges
        ]
    )


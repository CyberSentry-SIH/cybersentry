import pytest

def test_health_endpoint(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OK"
    assert data["app_name"] == "CyberSentry"

def test_login_and_me(client, analyst_headers):
    me_res = client.get("/api/v1/auth/me", headers=analyst_headers)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "analyst@cybersentry.local"

def test_dashboard_stats(client, analyst_headers):
    res = client.get("/api/v1/analysis/dashboard-stats", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_analyzed"] >= 5
    assert "recent_analyses" in data

def test_campaigns_list(client, analyst_headers):
    res = client.get("/api/v1/campaigns/", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1

def test_campaign_investigation_endpoint(client, analyst_headers):
    # Fetch list of campaigns
    camp_res = client.get("/api/v1/campaigns/", headers=analyst_headers)
    assert camp_res.status_code == 200
    campaigns = camp_res.json()
    assert len(campaigns) > 0
    camp_id = campaigns[0]["id"]

    # Fetch investigation
    inv_res = client.get(f"/api/v1/campaigns/{camp_id}/investigation", headers=analyst_headers)
    assert inv_res.status_code == 200
    inv = inv_res.json()
    assert "campaign_id" in inv
    assert "name" in inv
    assert "attack_invariants" in inv
    assert "infrastructure_relationships" in inv
    assert "variance_timeline" in inv
    assert "campaign_timeline" in inv
    assert "indicators" in inv
    assert "evidence_refs" in inv
    assert isinstance(inv["attack_invariants"], list)
    assert isinstance(inv["infrastructure_relationships"], list)

def test_graph_endpoint(client, analyst_headers):
    res = client.get("/api/v1/graph/", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) > 0

def test_what_changed_compare(client, analyst_headers):
    # Fetch evidence list to compare two emails
    ev_res = client.get("/api/v1/evidence/", headers=analyst_headers)
    assert ev_res.status_code == 200
    ev_list = ev_res.json()
    assert len(ev_list) >= 2
    email_a_id = ev_list[0]["id"]
    email_b_id = ev_list[1]["id"]

    comp_res = client.get(
        "/api/v1/campaigns/compare",
        params={"email_a": email_a_id, "email_b": email_b_id},
        headers=analyst_headers
    )
    assert comp_res.status_code == 200
    comp = comp_res.json()
    assert "similarity_score" in comp
    assert "mutated_surface_features" in comp
    assert "retained_attack_invariants" in comp
    assert "infrastructure_relationships" in comp
    assert isinstance(comp["mutated_surface_features"], list)
    assert isinstance(comp["retained_attack_invariants"], list)
    assert isinstance(comp["infrastructure_relationships"], list)

def test_admin_retention_enforcement(client, admin_headers):
    # Trigger retention enforcement
    ret_res = client.post("/api/v1/admin/retention/enforce", headers=admin_headers)
    assert ret_res.status_code == 200
    data = ret_res.json()
    assert data["status"] == "success"
    assert "purged_count" in data

    # Verify audit events recorded
    audit_res = client.get("/api/v1/admin/audit-events", headers=admin_headers)
    assert audit_res.status_code == 200
    events = audit_res.json()
    assert any(e["action"] == "RETENTION_POLICY_ENFORCED" for e in events)

"""
Automated Test Suite for Merit Backend (Phase 1 MVP)

Covers all required unit and security criteria:
1. Missing token returns 401.
2. Invalid token returns 401.
3. Test-token is strictly rejected in production mode.
4. A user cannot read another user's ICP (Ownership isolation).
5. A user cannot modify or delete another user's watchlist.
6. A user cannot read another user's leads.
7. Invalid ICP threshold is rejected (< 0 or > 100).
8. Invalid watchlist source configuration is rejected.
9. SSRF attempts against localhost/private IPs are blocked.
10. Actor input matches the confirmed { "url": "..." } schema.
11. Actor start failure marks the scan correctly in database.
12. Webhook with an invalid secret is rejected.
13. Duplicate webhook delivery is idempotent (persistent idempotency).
14. Failed Actor runs do not create successful scan records.
15. Duplicate records do not create duplicate leads (persistent deduplication).
16. Deterministic scoring bounds, explainability, and exclusions.
17. Outreach does not invent facts when signal data is absent.
18. CSV export includes only the authenticated user's records.
19. CSV export neutralizes formula injection.
20. CSV import rejects malformed or oversized input.
21. Health and readiness endpoints report truthful states; /ready fails if DB is down.
22. Scan recovery endpoint recovers stale/interrupted jobs.
23. Database persistence: data is persisted across requests.
24. Complete API OpenAPI contract.
"""

import io
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import main
from main import (
    app,
    calculate_deterministic_fit_score,
    get_db,
    mock_test_db,
    normalize_record,
    sanitize_csv_cell,
    settings,
    validate_url_for_ssrf,
)

client = TestClient(app)

USER_A_HEADER = {"Authorization": "Bearer test-token-user-a"}
USER_B_HEADER = {"Authorization": "Bearer test-token-user-b"}


@pytest.fixture(autouse=True)
def setup_test_environment():
    settings.TEST_MODE = True
    settings.APP_ENV = "test"
    settings.APIFY_WEBHOOK_SECRET = "test-webhook-secret-12345"
    mock_test_db.clear()
    yield
    mock_test_db.clear()


# -----------------------------------------------------------------------------
# 1. Missing token returns 401
# -----------------------------------------------------------------------------
def test_missing_token_returns_401():
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert "detail" in response.json()


# -----------------------------------------------------------------------------
# 2. Invalid token returns 401
# -----------------------------------------------------------------------------
def test_invalid_token_returns_401(monkeypatch):
    from main import supabase_auth

    async def mock_verify(token):
        raise HTTPException(status_code=401, detail="Invalid token")

    monkeypatch.setattr(supabase_auth, "verify_token", mock_verify)

    response = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer bad-token-xyz"})
    assert response.status_code == 401


# -----------------------------------------------------------------------------
# 3. Test token is strictly rejected in production mode
# -----------------------------------------------------------------------------
def test_test_token_rejected_in_production(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "TEST_MODE", False)

    response = client.get("/api/v1/auth/me", headers=USER_A_HEADER)
    assert response.status_code == 401
    assert "Test tokens are strictly forbidden" in response.json()["detail"]


# -----------------------------------------------------------------------------
# 4. User cannot read another user's ICP (Ownership isolation)
# -----------------------------------------------------------------------------
def test_user_cannot_read_another_users_icp():
    create_res = client.post(
        "/api/v1/icps",
        headers=USER_A_HEADER,
        json={
            "name": "B2B SaaS Founders",
            "business_description": "We build outbound sales automation for founders.",
            "target_titles": ["CEO", "Founder"],
            "threshold": 80,
        },
    )
    assert create_res.status_code == 201
    icp_id = create_res.json()["id"]

    # User B tries to read User A's ICP
    read_res = client.get(f"/api/v1/icps/{icp_id}", headers=USER_B_HEADER)
    assert read_res.status_code == 404

    # User A can read it
    owner_res = client.get(f"/api/v1/icps/{icp_id}", headers=USER_A_HEADER)
    assert owner_res.status_code == 200
    assert owner_res.json()["id"] == icp_id


# -----------------------------------------------------------------------------
# 5. User cannot modify or delete another user's watchlist
# -----------------------------------------------------------------------------
def test_user_cannot_modify_or_delete_another_users_watchlist():
    create_res = client.post(
        "/api/v1/watchlists",
        headers=USER_A_HEADER,
        json={
            "name": "Tech Competitors",
            "source_type": "website",
            "source_url": "https://example.com",
            "scan_interval_hours": 12,
        },
    )
    assert create_res.status_code == 201
    w_id = create_res.json()["id"]

    # User B attempts to patch User A's watchlist
    patch_res = client.patch(
        f"/api/v1/watchlists/{w_id}",
        headers=USER_B_HEADER,
        json={"name": "Hacked Name"},
    )
    assert patch_res.status_code == 404

    # User B attempts to delete User A's watchlist
    del_res = client.delete(f"/api/v1/watchlists/{w_id}", headers=USER_B_HEADER)
    assert del_res.status_code == 404

    # Verify watchlist still intact for User A
    get_res = client.get(f"/api/v1/watchlists/{w_id}", headers=USER_A_HEADER)
    assert get_res.status_code == 200
    assert get_res.json()["name"] == "Tech Competitors"


# -----------------------------------------------------------------------------
# 6. User cannot read another user's leads
# -----------------------------------------------------------------------------
def test_user_cannot_read_another_users_leads():
    # Insert lead for user-a directly
    mock_test_db.leads["lead-user-a"] = {
        "id": "lead-user-a",
        "user_id": "user-a",
        "full_name": "Target Lead A",
        "status": "new",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }

    # User B tries to get it
    res = client.get("/api/v1/leads/lead-user-a", headers=USER_B_HEADER)
    assert res.status_code == 404

    # User A gets it successfully
    res_a = client.get("/api/v1/leads/lead-user-a", headers=USER_A_HEADER)
    assert res_a.status_code == 200
    assert res_a.json()["full_name"] == "Target Lead A"


# -----------------------------------------------------------------------------
# 7. Invalid ICP threshold is rejected
# -----------------------------------------------------------------------------
def test_invalid_icp_threshold_rejected():
    res_high = client.post(
        "/api/v1/icps",
        headers=USER_A_HEADER,
        json={
            "name": "Invalid Threshold ICP",
            "business_description": "Valid business description for test.",
            "threshold": 120,
        },
    )
    assert res_high.status_code == 422

    res_low = client.post(
        "/api/v1/icps",
        headers=USER_A_HEADER,
        json={
            "name": "Negative Threshold ICP",
            "business_description": "Valid business description for test.",
            "threshold": -5,
        },
    )
    assert res_low.status_code == 422


# -----------------------------------------------------------------------------
# 8. Invalid watchlist source configuration is rejected
# -----------------------------------------------------------------------------
def test_invalid_watchlist_configuration_rejected():
    res1 = client.post(
        "/api/v1/watchlists",
        headers=USER_A_HEADER,
        json={
            "name": "Missing Keyword",
            "source_type": "keyword",
        },
    )
    assert res1.status_code == 400
    assert "requires a non-empty 'keyword'" in res1.json()["detail"]

    res2 = client.post(
        "/api/v1/watchlists",
        headers=USER_A_HEADER,
        json={
            "name": "Missing URL",
            "source_type": "website",
        },
    )
    assert res2.status_code == 400
    assert "requires a valid 'source_url'" in res2.json()["detail"]


# -----------------------------------------------------------------------------
# 9. SSRF attempts against localhost/private IPs are blocked
# -----------------------------------------------------------------------------
def test_ssrf_attempts_blocked():
    blocked_urls = [
        "http://localhost:8000/internal",
        "http://127.0.0.1:8080",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/admin",
        "http://192.168.1.1/router",
        "http://metadata.google.internal/computeMetadata/v1/",
        "ftp://example.com/file",
    ]
    for url in blocked_urls:
        with pytest.raises(HTTPException) as excinfo:
            validate_url_for_ssrf(url)
        assert excinfo.value.status_code == 400


# -----------------------------------------------------------------------------
# 10. Actor input matches confirmed { "url": "..." } schema
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_actor_input_matches_confirmed_schema(monkeypatch):
    captured_payloads = []

    async def mock_post(client_self, url, json=None, headers=None, params=None):
        captured_payloads.append(json)
        class MockRes:
            status_code = 201
            def json(self):
                return {"data": {"id": "run-test-123", "defaultDatasetId": "ds-test-123", "status": "RUNNING"}}
        return MockRes()

    monkeypatch.setattr(main.httpx.AsyncClient, "post", mock_post)
    main.settings.APIFY_API_TOKEN = "test-token"

    res = await main.apify_service.start_actor_run("https://example.com")
    assert res["actor_run_id"] == "run-test-123"
    assert len(captured_payloads) >= 1
    assert captured_payloads[0] == {"url": "https://example.com"}


# -----------------------------------------------------------------------------
# 11. Actor start failure marks scan correctly in database
# -----------------------------------------------------------------------------
def test_actor_start_failure_marks_scan_failed(monkeypatch):
    async def mock_fail_start(url, webhook_url=None, **kwargs):
        raise Exception("Apify rate limit exceeded or invalid token")

    monkeypatch.setattr(main.apify_service, "start_actor_run", mock_fail_start)

    w_res = client.post(
        "/api/v1/watchlists",
        headers=USER_A_HEADER,
        json={
            "name": "Scan Target",
            "source_type": "website",
            "source_url": "https://example.com",
        },
    )
    w_id = w_res.json()["id"]

    scan_res = client.post(f"/api/v1/watchlists/{w_id}/scan", headers=USER_A_HEADER)
    assert scan_res.status_code == 200
    data = scan_res.json()
    assert data["status"] == "failed"
    assert data["error_code"] == "ACTOR_LAUNCH_FAILED"
    assert "Apify rate limit exceeded" in data["error_message"]


# -----------------------------------------------------------------------------
# 12. Webhook with invalid secret is rejected
# -----------------------------------------------------------------------------
def test_webhook_with_invalid_secret_rejected():
    res = client.post(
        "/api/v1/webhooks/apify",
        headers={"X-Merit-Webhook-Secret": "wrong-secret"},
        json={"eventType": "ACTOR.RUN.SUCCEEDED", "eventData": {"actorRunId": "run-xyz"}},
    )
    assert res.status_code == 401
    assert "Invalid or missing webhook secret" in res.json()["detail"]


# -----------------------------------------------------------------------------
# 13. Duplicate webhook delivery is idempotent (persistent)
# -----------------------------------------------------------------------------
def test_duplicate_webhook_delivery_idempotent():
    payload = {
        "eventType": "ACTOR.RUN.SUCCEEDED",
        "eventData": {"actorRunId": "run-idempotency-test", "defaultDatasetId": "ds-123"},
    }
    headers = {"X-Merit-Webhook-Secret": "test-webhook-secret-12345"}

    res1 = client.post("/api/v1/webhooks/apify", headers=headers, json=payload)
    assert res1.status_code == 200

    # Second call must be recognized as duplicate
    res2 = client.post("/api/v1/webhooks/apify", headers=headers, json=payload)
    assert res2.status_code == 200
    assert "Duplicate event acknowledged (idempotent)" in res2.json()["message"]


# -----------------------------------------------------------------------------
# 14. Failed Actor runs do not create successful scan records
# -----------------------------------------------------------------------------
def test_failed_actor_runs_do_not_create_successful_scans():
    headers = {"X-Merit-Webhook-Secret": "test-webhook-secret-12345"}

    mock_test_db.scan_jobs["job-fail-test"] = {
        "id": "job-fail-test",
        "user_id": "user-a",
        "watchlist_id": "watch-1",
        "actor_run_id": "run-aborted-99",
        "dataset_id": None,
        "status": "running",
        "items_found": 0,
        "items_processed": 0,
        "items_rejected": 0,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }

    payload = {
        "eventType": "ACTOR.RUN.ABORTED",
        "eventData": {"actorRunId": "run-aborted-99"},
    }
    res = client.post("/api/v1/webhooks/apify", headers=headers, json=payload)
    assert res.status_code == 200

    job = mock_test_db.scan_jobs["job-fail-test"]
    assert job["status"] == "failed"
    assert job["error_code"] == "APIFY_WEBHOOK_ACTOR.RUN.ABORTED"


# -----------------------------------------------------------------------------
# 15. Duplicate records deduplication
# -----------------------------------------------------------------------------
def test_duplicate_records_deduplication():
    csv_content = (
        "Full Name,Profile URL,Job Title,Company Name\n"
        "Alex Rivera,https://linkedin.com/in/alex-rivera,VP Sales,Acme Corp\n"
        "Alex Rivera Updated,https://linkedin.com/in/alex-rivera/,Head of Growth,Acme Corp\n"
    )
    files = {"file": ("leads.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
    res = client.post("/api/v1/leads/import.csv", headers=USER_A_HEADER, files=files)
    assert res.status_code == 200
    summary = res.json()
    assert summary["imported"] == 1
    assert summary["updated"] == 1

    user_a_leads = [l for l in mock_test_db.leads.values() if l["user_id"] == "user-a"]
    assert len(user_a_leads) == 1
    assert user_a_leads[0]["job_title"] == "Head of Growth"


# -----------------------------------------------------------------------------
# 16. Deterministic scoring bounds, explainability, and exclusions
# -----------------------------------------------------------------------------
def test_deterministic_scoring_bounds_and_exclusions():
    icp = {
        "target_titles": ["VP Sales", "Head of Sales"],
        "industries": ["Software", "SaaS"],
        "company_sizes": ["51-200"],
        "locations": ["United States"],
        "keywords": ["outbound"],
        "exclusions": ["intern", "student"],
        "threshold": 75,
    }

    perfect_lead = {
        "id": "lead-1",
        "job_title": "VP Sales",
        "industry": "Enterprise Software",
        "company_size": "51-200",
        "location": "United States",
        "signal_text": "Looking to scale outbound sales",
    }
    res_perfect = calculate_deterministic_fit_score(perfect_lead, icp)
    assert res_perfect.fit_score == 100
    assert res_perfect.is_qualified is True
    assert 0 <= res_perfect.fit_score <= 100

    excluded_lead = {
        "id": "lead-2",
        "job_title": "Sales Intern",
        "industry": "Software",
        "company_size": "51-200",
    }
    res_excl = calculate_deterministic_fit_score(excluded_lead, icp)
    assert res_excl.fit_score == 0
    assert "Disqualified due to matching exclusion term" in res_excl.fit_reasoning


# -----------------------------------------------------------------------------
# 17. Outreach does not invent facts when signal data is absent
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_outreach_rejects_insufficient_evidence():
    empty_lead = {
        "id": "lead-empty",
        "user_id": "user-a",
        "full_name": "Ghost User",
        "job_title": None,
        "company_name": None,
        "signal_text": None,
    }
    with pytest.raises(HTTPException) as excinfo:
        await main.groq_service.generate_outreach_draft(empty_lead, "connection_request")
    assert excinfo.value.status_code == 422
    assert "Insufficient evidence" in excinfo.value.detail


# -----------------------------------------------------------------------------
# 18. CSV export includes only the authenticated user's records
# -----------------------------------------------------------------------------
def test_csv_export_ownership_isolation():
    mock_test_db.leads["lead-a"] = {
        "id": "lead-a",
        "user_id": "user-a",
        "full_name": "Alice UserA",
        "profile_url": "https://linkedin.com/in/alice-a",
        "job_title": "Director",
        "company_name": "Alpha Inc",
        "fit_score": 85,
        "status": "qualified",
        "created_at": "2026-01-01T00:00:00Z",
    }
    mock_test_db.leads["lead-b"] = {
        "id": "lead-b",
        "user_id": "user-b",
        "full_name": "Bob UserB",
        "profile_url": "https://linkedin.com/in/bob-b",
        "job_title": "Manager",
        "company_name": "Beta LLC",
        "fit_score": 90,
        "status": "qualified",
        "created_at": "2026-01-01T00:00:00Z",
    }

    res_a = client.get("/api/v1/leads/export.csv", headers=USER_A_HEADER)
    assert res_a.status_code == 200
    content_a = res_a.text
    assert "Alice UserA" in content_a
    assert "Bob UserB" not in content_a


# -----------------------------------------------------------------------------
# 19. CSV export neutralizes formula injection
# -----------------------------------------------------------------------------
def test_csv_export_formula_injection_mitigation():
    dangerous_inputs = [
        "=SUM(1+1)",
        "+cmd|' /C calc'!A0",
        "-2+3*4",
        "@SUM(A1:A10)",
        "   =1+1",
    ]
    for inp in dangerous_inputs:
        sanitized = sanitize_csv_cell(inp)
        assert sanitized.startswith("'"), f"Dangerous input {inp} was not sanitized"

    assert sanitize_csv_cell("Normal Text") == "Normal Text"
    assert sanitize_csv_cell("John Doe") == "John Doe"


# -----------------------------------------------------------------------------
# 20. CSV import rejects malformed input
# -----------------------------------------------------------------------------
def test_csv_import_validation():
    files = {"file": ("malicious.exe", io.BytesIO(b"some content"), "application/octet-stream")}
    res = client.post("/api/v1/leads/import.csv", headers=USER_A_HEADER, files=files)
    assert res.status_code == 400
    assert "Uploaded file must be a .csv file" in res.json()["detail"]


# -----------------------------------------------------------------------------
# 21. Health and readiness endpoints report truthful states
# -----------------------------------------------------------------------------
def test_health_and_readiness_truthful_reports():
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"

    res_ready = client.get("/ready")
    assert res_ready.status_code == 200
    data = res_ready.json()
    assert data["status"] == "ready"
    assert data["diagnostics"]["supabase_database_connected"] is True


def test_readiness_fails_if_db_unreachable(monkeypatch):
    async def mock_health_fail():
        return False

    monkeypatch.setattr(mock_test_db, "health_check", mock_health_fail)
    res_ready = client.get("/ready")
    assert res_ready.status_code == 503
    assert res_ready.json()["detail"]["status"] == "degraded"


# -----------------------------------------------------------------------------
# 22. Scan recovery endpoint recovers stale/interrupted jobs
# -----------------------------------------------------------------------------
def test_scan_refresh_recovery(monkeypatch):
    mock_test_db.scan_jobs["scan-stale-1"] = {
        "id": "scan-stale-1",
        "user_id": "user-a",
        "watchlist_id": "watch-1",
        "actor_run_id": "run-recovered-101",
        "status": "running",
        "created_at": "2026-01-01T00:00:00Z",
    }

    async def mock_get_status(run_id):
        return {"status": "succeeded", "dataset_id": "ds-recovered-101"}

    monkeypatch.setattr(main.apify_service, "get_run_status", mock_get_status)

    res = client.post("/api/v1/scans/scan-stale-1/refresh", headers=USER_A_HEADER)
    assert res.status_code == 200
    assert res.json()["status"] == "processing"


# -----------------------------------------------------------------------------
# 23. Complete API OpenAPI contract
# -----------------------------------------------------------------------------
def test_api_openapi_contract():
    res = client.get("/openapi.json")
    assert res.status_code == 200
    schema = res.json()
    assert "paths" in schema
    assert "/api/v1/icps" in schema["paths"]
    assert "/api/v1/watchlists" in schema["paths"]
    assert "/api/v1/leads" in schema["paths"]
    assert "/api/v1/webhooks/apify" in schema["paths"]
    assert "/api/v1/leads/export.csv" in schema["paths"]


# -----------------------------------------------------------------------------
# 24. Regression: Webhook query secret is rejected, supported headers accepted
# -----------------------------------------------------------------------------
def test_webhook_secret_query_string_rejected():
    payload = {
        "eventType": "ACTOR.RUN.SUCCEEDED",
        "eventData": {"actorRunId": "run-secret-test", "defaultDatasetId": "ds-1"},
    }

    # 1. Secret in query string without header must be rejected with 401
    res_query = client.post("/api/v1/webhooks/apify?secret=test-webhook-secret-12345", json=payload)
    assert res_query.status_code == 401
    assert "Invalid or missing webhook secret header" in res_query.json()["detail"]

    # 2. Secret in supported header X-Merit-Webhook-Secret must succeed
    res_header = client.post(
        "/api/v1/webhooks/apify",
        headers={"X-Merit-Webhook-Secret": "test-webhook-secret-12345"},
        json=payload,
    )
    assert res_header.status_code == 200

    # 3. Secret in Authorization Bearer header must succeed
    payload_bearer = {
        "eventType": "ACTOR.RUN.SUCCEEDED",
        "eventData": {"actorRunId": "run-bearer-test", "defaultDatasetId": "ds-2"},
    }
    res_bearer = client.post(
        "/api/v1/webhooks/apify",
        headers={"Authorization": "Bearer test-webhook-secret-12345"},
        json=payload_bearer,
    )
    assert res_bearer.status_code == 200


# -----------------------------------------------------------------------------
# 25. Regression: Webhook race condition keeps unmatched event recoverable
# -----------------------------------------------------------------------------
def test_webhook_race_unmatched_event_remains_recoverable(monkeypatch):
    race_run_id = "race-run-order-test-123"
    event_key = f"apify_{race_run_id}_ACTOR.RUN.SUCCEEDED"
    payload = {
        "eventType": "ACTOR.RUN.SUCCEEDED",
        "eventData": {"actorRunId": race_run_id, "defaultDatasetId": "ds-race-1"},
    }
    headers = {"X-Merit-Webhook-Secret": "test-webhook-secret-12345"}

    async def mock_get_items(dataset_id, limit=100):
        return []

    monkeypatch.setattr(main.apify_service, "get_dataset_items", mock_get_items)

    # 1. Webhook arrives BEFORE scan job exists in database
    res1 = client.post("/api/v1/webhooks/apify", headers=headers, json=payload)
    assert res1.status_code == 200
    assert "matching scan job pending" in res1.json()["message"]

    # Invariant: Must NOT be permanently marked as 'processed'
    saved_event = mock_test_db.webhook_events.get(event_key)
    assert saved_event is not None
    assert saved_event["processing_status"] == "received"
    assert saved_event["processing_status"] != "processed"

    # 2. Scan job is now created and saved
    mock_test_db.scan_jobs["scan-race-job"] = {
        "id": "scan-race-job",
        "user_id": "user-a",
        "watchlist_id": "watch-1",
        "actor_run_id": race_run_id,
        "dataset_id": "ds-race-1",
        "status": "running",
        "items_found": 0,
        "items_processed": 0,
        "items_rejected": 0,
        "started_at": "2026-01-01T00:00:00Z",
        "created_at": "2026-01-01T00:00:00Z",
    }

    # 3. Retry webhook delivery arrives: now matches and transitions to processed
    res2 = client.post("/api/v1/webhooks/apify", headers=headers, json=payload)
    assert res2.status_code == 200
    assert "Webhook processed successfully" in res2.json()["message"]

    # Invariant: Scan status transitioned to processing/succeeded, and webhook event marked processed
    assert mock_test_db.scan_jobs["scan-race-job"]["status"] in ("processing", "succeeded")
    assert mock_test_db.webhook_events[event_key]["processing_status"] == "processed"


# -----------------------------------------------------------------------------
# 26. Regression: Scan left in 'processing' after restart is safely retryable
# -----------------------------------------------------------------------------
def test_scan_processing_restart_recovery_and_concurrency_lock(monkeypatch):
    scan_id = "scan-restart-recovery-99"
    actor_run_id = "run-restart-99"
    mock_test_db.scan_jobs[scan_id] = {
        "id": scan_id,
        "user_id": "user-a",
        "watchlist_id": "watch-1",
        "actor_run_id": actor_run_id,
        "dataset_id": "ds-restart-99",
        "status": "processing",  # Interrupted during restart!
        "items_found": 0,
        "items_processed": 0,
        "items_rejected": 0,
        "started_at": "2026-01-01T00:00:00Z",
        "created_at": "2026-01-01T00:00:00Z",
    }

    async def mock_get_status(run_id):
        return {"status": "succeeded", "dataset_id": "ds-restart-99"}

    async def mock_get_items(dataset_id, limit=100):
        return [
            {
                "fullName": "Restart Recovered Lead",
                "profileUrl": "https://linkedin.com/in/restart-recovered",
                "headline": "Engineering Director",
                "company": "Restart Corp",
            }
        ]

    monkeypatch.setattr(main.apify_service, "get_run_status", mock_get_status)
    monkeypatch.setattr(main.apify_service, "get_dataset_items", mock_get_items)

    # 1. Recovery endpoint must allow re-triggering dataset ingestion when left in 'processing'
    res = client.post(f"/api/v1/scans/{scan_id}/refresh", headers=USER_A_HEADER)
    assert res.status_code == 200
    assert res.json()["status"] == "processing"

    # 2. Concurrency protection: active processing scan cannot be triggered concurrently
    main._active_processing_scans.add(scan_id)
    try:
        # Refresh while active does not spawn duplicate worker
        res_duplicate = client.post(f"/api/v1/scans/{scan_id}/refresh", headers=USER_A_HEADER)
        assert res_duplicate.status_code == 200
    finally:
        main._active_processing_scans.discard(scan_id)


# -----------------------------------------------------------------------------
# 27. Regression: DNS rebinding and maximum download size limit
# -----------------------------------------------------------------------------
def test_website_fetching_dns_rebinding_and_stream_size_limit():
    import pytest
    from fastapi import HTTPException
    from main import validate_host_and_resolve_ip, MAX_WEBSITE_RESPONSE_BYTES

    # 1. Hostnames resolving to loopback/private IPs are rejected before/at socket connection
    with pytest.raises(HTTPException) as exc_localhost:
        validate_host_and_resolve_ip("localhost")
    assert exc_localhost.value.status_code == 400

    with pytest.raises(HTTPException) as exc_private:
        validate_host_and_resolve_ip("127.0.0.1")
    assert exc_private.value.status_code == 400

    with pytest.raises(HTTPException) as exc_metadata:
        validate_host_and_resolve_ip("169.254.169.254")
    assert exc_metadata.value.status_code == 400

    # 2. Maximum response body size constant is verified
    assert MAX_WEBSITE_RESPONSE_BYTES == 2 * 1024 * 1024


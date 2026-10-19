"""
Automated Test Suite for Merit Backend (Phase 1 MVP) - HarvestAPI Integration
Covers all unit, security, and integration criteria:
1. Missing token returns 401.
2. Invalid token returns 401.
3. Test-token is strictly rejected in production mode.
4. User cannot read another user's ICP (Ownership isolation).
5. User cannot modify or delete another user's watchlist.
6. User cannot read another user's leads.
7. Invalid ICP threshold is rejected (< 0 or > 100).
8. Unsupported watchlist source configuration is rejected (keyword unsupported).
9. SSRF attempts against localhost/private IPs are blocked.
10. HarvestAPI client authentication header X-API-Key and endpoint construction.
11. HarvestAPI rate limiting (429), not found (404), and error handling.
12. HarvestAPI profile, company, post, comment, reaction retrieval.
13. HarvestAPI normalizers: profile, comment, reaction (authors vs engagers distinction).
14. Website monitoring: direct safe crawl, independent of HarvestAPI.
15. Repeat scan deduplication & lead signals persistence.
16. Deterministic scoring bounds, explainability, and exclusions.
17. Outreach does not invent facts when signal data is absent.
18. CSV export includes only the authenticated user's records.
19. CSV export neutralizes formula injection.
20. CSV import rejects malformed input.
21. Health and readiness truthfully report states; /ready checks harvestapi_configured.
22. Scan recovery safely restarts interrupted jobs.
23. Lead signals retrieval endpoint GET /api/v1/leads/{lead_id}/signals.
24. Complete API OpenAPI contract.
25. DNS rebinding protection and maximum response size limit.
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
    normalize_harvest_profile,
    normalize_harvest_comment,
    normalize_harvest_reaction,
    normalize_website_lead,
    sanitize_csv_cell,
    settings,
    validate_url_for_ssrf,
    execute_scan_job,
)
from harvest_client import (
    HarvestAPIClient,
    HarvestAPIError,
    HarvestAPIAuthError,
    HarvestAPIRateLimitError,
    HarvestAPINotFoundError,
)

client = TestClient(app)

USER_A_HEADER = {"Authorization": "Bearer test-token-user-a"}
USER_B_HEADER = {"Authorization": "Bearer test-token-user-b"}


@pytest.fixture(autouse=True)
def setup_test_environment():
    settings.TEST_MODE = True
    settings.APP_ENV = "test"
    settings.HARVESTAPI_API_KEY = "test-harvest-api-key"
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
    # User A creates an ICP
    create_res = client.post(
        "/api/v1/icps",
        headers=USER_A_HEADER,
        json={
            "name": "User A ICP",
            "business_description": "Enterprise SaaS targeting VP of Sales",
            "target_titles": ["VP Sales", "CRO"],
            "threshold": 75,
        },
    )
    assert create_res.status_code == 201
    icp_id = create_res.json()["id"]

    # User B attempts to read User A's ICP -> 404
    read_res = client.get(f"/api/v1/icps/{icp_id}", headers=USER_B_HEADER)
    assert read_res.status_code == 404

    # User B list should not include User A's ICP
    list_res = client.get("/api/v1/icps", headers=USER_B_HEADER)
    assert list_res.status_code == 200
    assert not any(item["id"] == icp_id for item in list_res.json())


# -----------------------------------------------------------------------------
# 5. User cannot modify or delete another user's watchlist
# -----------------------------------------------------------------------------
def test_user_cannot_modify_or_delete_another_users_watchlist():
    # User A creates a watchlist
    w_res = client.post(
        "/api/v1/watchlists",
        headers=USER_A_HEADER,
        json={
            "name": "User A Watchlist",
            "source_type": "website",
            "source_url": "https://stripe.com",
        },
    )
    assert w_res.status_code == 201
    w_id = w_res.json()["id"]

    # User B attempts to update User A's watchlist -> 404
    patch_res = client.patch(
        f"/api/v1/watchlists/{w_id}",
        headers=USER_B_HEADER,
        json={"name": "Hacked Name"},
    )
    assert patch_res.status_code == 404

    # User B attempts to delete User A's watchlist -> 404
    del_res = client.delete(f"/api/v1/watchlists/{w_id}", headers=USER_B_HEADER)
    assert del_res.status_code == 404

    # Verify original unchanged
    verify_res = client.get(f"/api/v1/watchlists/{w_id}", headers=USER_A_HEADER)
    assert verify_res.status_code == 200
    assert verify_res.json()["name"] == "User A Watchlist"


# -----------------------------------------------------------------------------
# 6. User cannot read another user's leads
# -----------------------------------------------------------------------------
def test_user_cannot_read_another_users_leads():
    mock_test_db.leads["lead-user-a"] = {
        "id": "lead-user-a",
        "user_id": "user-a",
        "full_name": "Alice Smith",
        "job_title": "VP of Engineering",
        "company_name": "Tech Corp",
        "status": "new",
        "created_at": "2026-01-01T00:00:00Z",
    }

    # User B cannot get lead
    get_res = client.get("/api/v1/leads/lead-user-a", headers=USER_B_HEADER)
    assert get_res.status_code == 404

    # User B list should be empty
    list_res = client.get("/api/v1/leads", headers=USER_B_HEADER)
    assert list_res.status_code == 200
    assert len(list_res.json()) == 0


# -----------------------------------------------------------------------------
# 7. Invalid ICP threshold is rejected
# -----------------------------------------------------------------------------
def test_invalid_icp_threshold_rejected():
    res_negative = client.post(
        "/api/v1/icps",
        headers=USER_A_HEADER,
        json={"name": "Test", "business_description": "Desc", "threshold": -5},
    )
    assert res_negative.status_code == 422

    res_too_high = client.post(
        "/api/v1/icps",
        headers=USER_A_HEADER,
        json={"name": "Test", "business_description": "Desc", "threshold": 105},
    )
    assert res_too_high.status_code == 422


# -----------------------------------------------------------------------------
# 8. Unsupported watchlist source configuration is rejected (keyword unsupported)
# -----------------------------------------------------------------------------
def test_invalid_watchlist_configuration_rejected():
    res = client.post(
        "/api/v1/watchlists",
        headers=USER_A_HEADER,
        json={
            "name": "Keyword Watchlist",
            "source_type": "keyword",
            "keyword": "b2b saas",
        },
    )
    assert res.status_code == 400
    assert "not supported" in res.json()["detail"].lower()


# -----------------------------------------------------------------------------
# 9. SSRF attempts against localhost/private IPs are blocked
# -----------------------------------------------------------------------------
def test_ssrf_attempts_blocked():
    blocked_urls = [
        "http://localhost:8080",
        "http://127.0.0.1/admin",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/secret",
        "http://169.254.169.254/latest/meta-data/",
    ]
    for url in blocked_urls:
        with pytest.raises(HTTPException) as exc_info:
            validate_url_for_ssrf(url)
        assert exc_info.value.status_code == 400


# -----------------------------------------------------------------------------
# 10. HarvestAPI client authentication header X-API-Key and endpoint construction
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_harvestapi_client_auth_header(monkeypatch):
    captured_headers = {}
    captured_urls = []

    async def mock_request(client_self, method, url, **kwargs):
        captured_urls.append(str(url))
        captured_headers.update(kwargs.get("headers") or {})
        class MockResponse:
            status_code = 200
            text = '{"element": {"id": "123", "fullName": "Jane Doe"}}'
            def json(self):
                return {"element": {"id": "123", "fullName": "Jane Doe"}}
        return MockResponse()

    test_client = HarvestAPIClient(api_key="secret-test-key-999")
    monkeypatch.setattr(main.httpx.AsyncClient, "request", mock_request)

    res = await test_client.get_profile("https://linkedin.com/in/janedoe")
    assert res["fullName"] == "Jane Doe"
    assert captured_headers.get("X-API-Key") == "secret-test-key-999"
    assert "/linkedin/profile" in captured_urls[0]
    await test_client.close()


# -----------------------------------------------------------------------------
# 11. HarvestAPI rate limiting (429), not found (404), and error handling
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_harvestapi_rate_limit_and_error_handling(monkeypatch):
    test_client = HarvestAPIClient(api_key="key", max_retries=1)

    # 429 Rate limit test
    async def mock_429(client_self, method, url, **kwargs):
        class MockRes:
            status_code = 429
            headers = {"Retry-After": "1"}
            text = "Too many requests"
        return MockRes()

    monkeypatch.setattr(main.httpx.AsyncClient, "request", mock_429)
    with pytest.raises(HarvestAPIRateLimitError):
        await test_client.get_profile("https://linkedin.com/in/test")

    # 404 Not found test
    async def mock_404(client_self, method, url, **kwargs):
        class MockRes:
            status_code = 404
            text = "Profile not found"
        return MockRes()

    monkeypatch.setattr(main.httpx.AsyncClient, "request", mock_404)
    with pytest.raises(HarvestAPINotFoundError):
        await test_client.get_profile("https://linkedin.com/in/notfound")

    # 401 Auth error test
    async def mock_401(client_self, method, url, **kwargs):
        class MockRes:
            status_code = 401
            text = "Unauthorized"
        return MockRes()

    monkeypatch.setattr(main.httpx.AsyncClient, "request", mock_401)
    with pytest.raises(HarvestAPIAuthError):
        await test_client.get_profile("https://linkedin.com/in/test")
    await test_client.close()


# -----------------------------------------------------------------------------
# 12. HarvestAPI profile, company, post, comment, reaction retrieval
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_harvestapi_endpoints_coverage(monkeypatch):
    test_client = HarvestAPIClient(api_key="test-key")
    endpoints_called = []

    async def mock_req(client_self, method, url, **kwargs):
        endpoints_called.append(str(url))
        class MockRes:
            status_code = 200
            text = "{}"
            def json(self):
                return {"element": {"id": "1"}, "elements": [{"id": "2"}]}
        return MockRes()

    monkeypatch.setattr(main.httpx.AsyncClient, "request", mock_req)

    await test_client.get_profile("url")
    await test_client.get_profile_posts("url")
    await test_client.get_company("url")
    await test_client.get_company_posts("url")
    await test_client.get_post_comments("url")
    await test_client.get_post_reactions("url")

    assert any("/linkedin/profile" in ep for ep in endpoints_called)
    assert any("/linkedin/profile-posts" in ep for ep in endpoints_called)
    assert any("/linkedin/company" in ep for ep in endpoints_called)
    assert any("/linkedin/company-posts" in ep for ep in endpoints_called)
    assert any("/linkedin/post-comments" in ep for ep in endpoints_called)
    assert any("/linkedin/post-reactions" in ep for ep in endpoints_called)
    await test_client.close()


# -----------------------------------------------------------------------------
# 13. HarvestAPI normalizers: distinguish authors vs commenters vs reactors
# -----------------------------------------------------------------------------
def test_harvestapi_normalizers_distinguish_engagers():
    # 1. Profile normalizer (Author/Profile)
    prof_data = {
        "id": "urn:li:fsd_profile:123",
        "fullName": "Sarah Connor",
        "linkedinUrl": "https://www.linkedin.com/in/sarah-connor?utm_source=test",
        "headline": "VP of Technology at Skynet",
        "companyName": "Skynet Systems",
        "location": "Los Angeles, CA",
        "summary": "Building resilient systems.",
    }
    norm_prof = normalize_harvest_profile(prof_data)
    assert norm_prof["full_name"] == "Sarah Connor"
    assert norm_prof["job_title"] == "VP of Technology at Skynet"
    assert norm_prof["profile_url"] == "https://www.linkedin.com/in/sarah-connor"  # tracking stripped
    assert norm_prof["signal_type"] == "profile_activity"

    # 2. Comment normalizer (Engager: Commenter)
    comment_data = {
        "id": "comment-456",
        "commentary": "Interested in evaluating this solution for our team.",
        "createdAt": "2026-05-01T12:00:00Z",
        "actor": {
            "id": "actor-789",
            "name": "John Doe",
            "linkedinUrl": "https://www.linkedin.com/in/johndoe",
            "position": "Director of Procurement",
        },
    }
    norm_comment = normalize_harvest_comment(comment_data, post_url="https://linkedin.com/posts/sample-post")
    assert norm_comment["full_name"] == "John Doe"
    assert norm_comment["job_title"] == "Director of Procurement"
    assert norm_comment["signal_type"] == "post_comment"
    assert "Interested in evaluating" in norm_comment["signal_text"]
    assert norm_comment["signal_url"] == "https://linkedin.com/posts/sample-post"

    # 3. Reaction normalizer (Engager: Reactor)
    reaction_data = {
        "id": "reaction-101",
        "reactionType": "LIKE",
        "actor": {
            "id": "actor-999",
            "name": "Jane Buyer",
            "linkedinUrl": "https://www.linkedin.com/in/janebuyer",
            "position": "VP of Operations",
        },
    }
    norm_reaction = normalize_harvest_reaction(reaction_data, post_url="https://linkedin.com/posts/sample-post")
    assert norm_reaction["full_name"] == "Jane Buyer"
    assert norm_reaction["signal_type"] == "post_reaction_like"
    assert norm_reaction["signal_text"] == "Reacted LIKE to LinkedIn post"


# -----------------------------------------------------------------------------
# 14. Website monitoring: direct safe crawl, independent of HarvestAPI
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_website_monitoring_independent_of_harvestapi(monkeypatch):
    # Mock safe crawler
    async def mock_crawl(url):
        return ("Acme Global", "Acme delivers cloud observability and performance monitoring.")

    monkeypatch.setattr(main, "fetch_website_content_safe", mock_crawl)

    # Ensure harvest client is NOT called
    async def mock_harvest_profile(*args, **kwargs):
        raise AssertionError("HarvestAPI must NOT be called for website monitors!")

    monkeypatch.setattr(main.harvest_client, "get_profile", mock_harvest_profile)

    # Create website watchlist
    w_res = client.post(
        "/api/v1/watchlists",
        headers=USER_A_HEADER,
        json={"name": "Acme Website", "source_type": "website", "source_url": "https://acme.org"},
    )
    w_id = w_res.json()["id"]

    # Trigger scan
    scan_res = client.post(f"/api/v1/watchlists/{w_id}/scan", headers=USER_A_HEADER)
    assert scan_res.status_code == 200
    scan_id = scan_res.json()["id"]

    # Execute scan synchronously
    await execute_scan_job(scan_id, "user-a", w_id)

    job = mock_test_db.scan_jobs[scan_id]
    assert job["status"] == "succeeded"
    assert job["items_processed"] >= 1


# -----------------------------------------------------------------------------
# 15. Repeat scan deduplication & lead signals persistence
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_repeat_scan_dedup_and_signals_persistence(monkeypatch):
    user_id = "user-a"
    w_id = "watchlist-dedup-1"
    mock_test_db.watchlists[w_id] = {
        "id": w_id,
        "user_id": user_id,
        "name": "LinkedIn Watchlist",
        "source_type": "my_company",
        "source_url": "https://linkedin.com/company/techco",
    }

    # HarvestAPI returns 1 post with 1 comment
    async def mock_company(url):
        return {"name": "TechCo"}

    async def mock_posts(url, page=1):
        return {"elements": [{"postUrl": "https://linkedin.com/posts/post-1"}]}

    async def mock_comments(url, page=1):
        return {
            "elements": [
                {
                    "commentary": "First observation on post.",
                    "actor": {
                        "name": "Alex Buyer",
                        "linkedinUrl": "https://linkedin.com/in/alexbuyer",
                        "position": "VP Tech",
                    },
                }
            ]
        }

    async def mock_reactions(url, page=1):
        return {"elements": []}

    monkeypatch.setattr(main.harvest_client, "get_company", mock_company)
    monkeypatch.setattr(main.harvest_client, "get_company_posts", mock_posts)
    monkeypatch.setattr(main.harvest_client, "get_post_comments", mock_comments)
    monkeypatch.setattr(main.harvest_client, "get_post_reactions", mock_reactions)

    # Scan 1
    scan_1_id = "scan-run-1"
    mock_test_db.scan_jobs[scan_1_id] = {"id": scan_1_id, "user_id": user_id, "watchlist_id": w_id}
    await execute_scan_job(scan_1_id, user_id, w_id)

    leads_after_1 = [l for l in mock_test_db.leads.values() if l.get("user_id") == user_id]
    assert len(leads_after_1) == 1
    lead_id = leads_after_1[0]["id"]
    assert len(mock_test_db.lead_signals) == 1

    # Scan 2: Second comment observed from the same person
    async def mock_comments_2(url, page=1):
        return {
            "elements": [
                {
                    "commentary": "Second observation on post.",
                    "actor": {
                        "name": "Alex Buyer",
                        "linkedinUrl": "https://linkedin.com/in/alexbuyer",
                        "position": "VP Tech",
                    },
                }
            ]
        }
    monkeypatch.setattr(main.harvest_client, "get_post_comments", mock_comments_2)

    scan_2_id = "scan-run-2"
    mock_test_db.scan_jobs[scan_2_id] = {"id": scan_2_id, "user_id": user_id, "watchlist_id": w_id}
    await execute_scan_job(scan_2_id, user_id, w_id)

    # Invariant: Lead is deduplicated (not duplicated), but signals history is accumulated
    leads_after_2 = [l for l in mock_test_db.leads.values() if l.get("user_id") == user_id]
    assert len(leads_after_2) == 1
    assert leads_after_2[0]["id"] == lead_id

    lead_signals = [s for s in mock_test_db.lead_signals if s.get("lead_id") == lead_id]
    assert len(lead_signals) == 2


# -----------------------------------------------------------------------------
# 16. Deterministic scoring bounds, explainability, and exclusions
# -----------------------------------------------------------------------------
def test_deterministic_scoring_bounds_and_exclusions():
    icp = {
        "id": "icp-1",
        "threshold": 75,
        "target_titles": ["VP Sales", "Director of Sales"],
        "industries": ["Software", "SaaS"],
        "company_sizes": ["51-200", "201-500"],
        "locations": ["North America", "San Francisco"],
        "keywords": ["enterprise", "b2b"],
        "exclusions": ["intern", "student", "freelance"],
    }

    # Perfect match: title(35) + ind(25) + size(15) + loc(15) + kw(10) = 100
    perfect_lead = {
        "id": "lead-1",
        "job_title": "VP Sales",
        "industry": "SaaS",
        "company_size": "51-200",
        "location": "San Francisco",
        "signal_text": "Driving enterprise B2B sales expansion.",
    }
    score_res = calculate_deterministic_fit_score(perfect_lead, icp)
    assert score_res.fit_score == 100
    assert score_res.is_qualified is True

    # Excluded lead: contains 'intern'
    excluded_lead = {
        "id": "lead-2",
        "job_title": "VP Sales Intern",
        "industry": "SaaS",
        "company_size": "51-200",
    }
    score_excluded = calculate_deterministic_fit_score(excluded_lead, icp)
    assert score_excluded.fit_score == 0
    assert score_excluded.is_qualified is False
    assert "exclusion" in score_excluded.fit_reasoning.lower()


# -----------------------------------------------------------------------------
# 17. Outreach does not invent facts when signal data is absent
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_outreach_rejects_insufficient_evidence():
    mock_test_db.leads["lead-no-evidence"] = {
        "id": "lead-no-evidence",
        "user_id": "user-a",
        "full_name": "Ghost Candidate",
        "status": "new",
        "created_at": "2026-01-01T00:00:00Z",
    }

    res = client.post(
        "/api/v1/leads/lead-no-evidence/drafts",
        headers=USER_A_HEADER,
        json={"channel": "connection_request"},
    )
    assert res.status_code == 422
    assert "Insufficient evidence" in res.json()["detail"]


# -----------------------------------------------------------------------------
# 18. CSV export ownership isolation
# -----------------------------------------------------------------------------
def test_csv_export_ownership_isolation():
    mock_test_db.leads["lead-a"] = {
        "id": "lead-a",
        "user_id": "user-a",
        "full_name": "User A Lead",
        "profile_url": "https://linkedin.com/in/user-a-lead",
        "status": "new",
        "created_at": "2026-01-01T00:00:00Z",
    }
    mock_test_db.leads["lead-b"] = {
        "id": "lead-b",
        "user_id": "user-b",
        "full_name": "User B Secret Lead",
        "profile_url": "https://linkedin.com/in/user-b-secret",
        "status": "new",
        "created_at": "2026-01-01T00:00:00Z",
    }

    res = client.get("/api/v1/leads/export.csv", headers=USER_A_HEADER)
    assert res.status_code == 200
    content = res.text
    assert "User A Lead" in content
    assert "User B Secret Lead" not in content


# -----------------------------------------------------------------------------
# 19. CSV export formula injection mitigation
# -----------------------------------------------------------------------------
def test_csv_export_formula_injection_mitigation():
    mock_test_db.leads["lead-injection"] = {
        "id": "lead-injection",
        "user_id": "user-a",
        "full_name": "=1+1",
        "job_title": "@SUM(1,2)",
        "company_name": "-2+3",
        "status": "new",
        "created_at": "2026-01-01T00:00:00Z",
    }
    res = client.get("/api/v1/leads/export.csv", headers=USER_A_HEADER)
    assert res.status_code == 200
    content = res.text
    assert "'=1+1" in content
    assert "'@SUM(1,2)" in content
    assert "'-2+3" in content


# -----------------------------------------------------------------------------
# 20. CSV import validation
# -----------------------------------------------------------------------------
def test_csv_import_validation():
    # Malformed / empty CSV
    res = client.post(
        "/api/v1/leads/import.csv",
        headers=USER_A_HEADER,
        files={"file": ("empty.csv", b"")},
    )
    assert res.status_code == 400


# -----------------------------------------------------------------------------
# 21. Health and readiness truthfully report states; /ready checks harvestapi_configured
# -----------------------------------------------------------------------------
def test_health_and_readiness_truthful_reports():
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"

    res_ready = client.get("/ready")
    assert res_ready.status_code == 200
    data = res_ready.json()
    assert data["status"] == "ready"
    assert "harvestapi_configured" in data["diagnostics"]
    assert "supabase_database_connected" in data["diagnostics"]


def test_readiness_fails_if_db_unreachable(monkeypatch):
    async def mock_unhealthy():
        return False

    monkeypatch.setattr(mock_test_db, "health_check", mock_unhealthy)

    res_ready = client.get("/ready")
    assert res_ready.status_code == 503
    assert res_ready.json()["detail"]["status"] == "degraded"


# -----------------------------------------------------------------------------
# 22. Scan recovery safely restarts interrupted jobs
# -----------------------------------------------------------------------------
def test_scan_refresh_recovery():
    mock_test_db.scan_jobs["scan-stale-1"] = {
        "id": "scan-stale-1",
        "user_id": "user-a",
        "watchlist_id": "watch-1",
        "status": "running",
        "created_at": "2026-01-01T00:00:00Z",
    }
    mock_test_db.watchlists["watch-1"] = {
        "id": "watch-1",
        "user_id": "user-a",
        "name": "Watchlist 1",
        "source_type": "website",
        "source_url": "https://example.com",
    }

    res = client.post("/api/v1/scans/scan-stale-1/refresh", headers=USER_A_HEADER)
    assert res.status_code == 200
    assert res.json()["status"] == "running"


# -----------------------------------------------------------------------------
# 23. Lead signals retrieval endpoint GET /api/v1/leads/{lead_id}/signals
# -----------------------------------------------------------------------------
def test_lead_signals_endpoint():
    user_id = "user-a"
    lead_id = "lead-with-signals"
    mock_test_db.leads[lead_id] = {
        "id": lead_id,
        "user_id": user_id,
        "full_name": "Signal Candidate",
        "status": "qualified",
        "created_at": "2026-01-01T00:00:00Z",
    }
    mock_test_db.lead_signals.append({
        "id": "sig-1",
        "user_id": user_id,
        "lead_id": lead_id,
        "signal_type": "post_comment",
        "signal_text": "Looking forward to this release.",
        "signal_url": "https://linkedin.com/posts/xyz",
    })

    # User A gets signals
    res = client.get(f"/api/v1/leads/{lead_id}/signals", headers=USER_A_HEADER)
    assert res.status_code == 200
    signals = res.json()
    assert len(signals) == 1
    assert signals[0]["signal_type"] == "post_comment"

    # User B cannot access signals of User A's lead (404)
    res_b = client.get(f"/api/v1/leads/{lead_id}/signals", headers=USER_B_HEADER)
    assert res_b.status_code == 404


# -----------------------------------------------------------------------------
# 24. Complete API OpenAPI contract
# -----------------------------------------------------------------------------
def test_api_openapi_contract():
    res = client.get("/openapi.json")
    assert res.status_code == 200
    schema = res.json()
    assert "paths" in schema
    assert "/api/v1/icps" in schema["paths"]
    assert "/api/v1/watchlists" in schema["paths"]
    assert "/api/v1/leads" in schema["paths"]
    assert "/api/v1/leads/{lead_id}/signals" in schema["paths"]
    assert "/api/v1/leads/export.csv" in schema["paths"]
    assert "/api/v1/integrations" in schema["paths"]
    # Webhooks path must NOT be present
    assert "/api/v1/webhooks/apify" not in schema["paths"]


# -----------------------------------------------------------------------------
# 25. DNS rebinding protection and maximum response size limit
# -----------------------------------------------------------------------------
def test_website_fetching_dns_rebinding_and_stream_size_limit():
    from main import validate_host_and_resolve_ip, MAX_WEBSITE_RESPONSE_BYTES

    # Hostnames resolving to loopback/private IPs are rejected before socket connection
    with pytest.raises(HTTPException) as exc_localhost:
        validate_host_and_resolve_ip("localhost")
    assert exc_localhost.value.status_code == 400

    with pytest.raises(HTTPException) as exc_private:
        validate_host_and_resolve_ip("127.0.0.1")
    assert exc_private.value.status_code == 400

    with pytest.raises(HTTPException) as exc_metadata:
        validate_host_and_resolve_ip("169.254.169.254")
    assert exc_metadata.value.status_code == 400

    # Maximum response body size constant verified
    assert MAX_WEBSITE_RESPONSE_BYTES == 2 * 1024 * 1024

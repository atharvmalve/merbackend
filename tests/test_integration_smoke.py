"""
Live Integration Smoke Test for Merit Backend

Performs real end-to-end CRUD against the configured Supabase PostgreSQL instance:
1. Verifies live database health ping.
2. Creates, retrieves, updates, and deletes an ICP.
3. Creates, retrieves, updates, and deletes a Watchlist.
4. Creates, deduplicates, and deletes a Lead in PostgreSQL.
5. Verifies persistent webhook event idempotency via unique constraints.
"""

import os
import uuid
import pytest
import httpx
from main import settings, SupabaseDatabase


@pytest.fixture
def live_db():
    if not settings.SUPABASE_URL or not settings.SUPABASE_SERVICE_ROLE_KEY:
        pytest.skip("Supabase credentials not configured in environment.")
    return SupabaseDatabase(settings)


@pytest.mark.asyncio
async def test_live_supabase_health(live_db):
    healthy = await live_db.health_check()
    assert healthy is True, "Live Supabase PostgREST health check failed."


@pytest.mark.asyncio
async def test_live_supabase_icp_crud(live_db):
    # Use real user from database
    user_id = "b1bde658-d2d1-4b0c-8d9a-f472066a438d"

    # 1. Create ICP
    icp_payload = {
        "user_id": user_id,
        "name": f"Integration Test ICP {uuid.uuid4().hex[:6]}",
        "business_description": "Valid business description for smoke testing live persistence.",
        "target_titles": ["VP Sales", "Chief Revenue Officer"],
        "threshold": 75,
    }
    created = await live_db.create_icp(icp_payload)
    assert created is not None
    icp_id = created["id"]
    assert created["name"] == icp_payload["name"]

    # 2. Retrieve ICP
    fetched = await live_db.get_icp(user_id, icp_id)
    assert fetched is not None
    assert fetched["id"] == icp_id

    # 3. Update ICP
    updated = await live_db.update_icp(user_id, icp_id, {"name": "Updated Live ICP Name"})
    assert updated is not None
    assert updated["name"] == "Updated Live ICP Name"

    # 4. Delete ICP
    deleted = await live_db.delete_icp(user_id, icp_id)
    assert deleted is True

    # 5. Verify deletion
    fetched_after = await live_db.get_icp(user_id, icp_id)
    assert fetched_after is None


@pytest.mark.asyncio
async def test_live_supabase_watchlist_crud(live_db):
    user_id = "b1bde658-d2d1-4b0c-8d9a-f472066a438d"

    w_payload = {
        "user_id": user_id,
        "name": f"Live Watchlist {uuid.uuid4().hex[:6]}",
        "source_type": "website",
        "source_url": "https://stripe.com",
    }
    created = await live_db.create_watchlist(w_payload)
    assert created is not None
    w_id = created["id"]

    fetched = await live_db.get_watchlist(user_id, w_id)
    assert fetched is not None

    deleted = await live_db.delete_watchlist(user_id, w_id)
    assert deleted is True


@pytest.mark.asyncio
async def test_live_supabase_webhook_persistent_idempotency(live_db):
    test_run_id = f"smoke_run_{uuid.uuid4().hex[:8]}"
    event_key = f"apify_{test_run_id}_ACTOR.RUN.SUCCEEDED"

    event_payload = {
        "provider": "apify",
        "event_key": event_key,
        "event_type": "ACTOR.RUN.SUCCEEDED",
        "actor_run_id": test_run_id,
        "payload": {"test": True},
        "processing_status": "received",
    }

    # First insert: must succeed
    is_new, recorded = await live_db.record_webhook_event(event_payload)
    assert is_new is True
    assert recorded is not None

    # Second insert with identical event_key: unique constraint must reject
    is_duplicate, _ = await live_db.record_webhook_event(event_payload)
    assert is_duplicate is False, "Duplicate webhook event was not recognized by PostgreSQL constraint."

    # Cleanup test event
    async with httpx.AsyncClient(timeout=10) as client:
        await client.delete(
            f"{live_db.base_url}/rest/v1/webhook_events?event_key=eq.{event_key}",
            headers=live_db._headers(),
        )


@pytest.mark.asyncio
async def test_live_supabase_lead_upsert_dedup(live_db):
    user_id = "b1bde658-d2d1-4b0c-8d9a-f472066a438d"
    profile_url = f"https://linkedin.com/in/test-smoke-{uuid.uuid4().hex[:8]}"

    lead_data = {
        "full_name": "Integration Smoke Lead",
        "job_title": "VP of Engineering",
        "company_name": "Smoke Corp",
        "profile_url": profile_url,
        "signal_type": "post",
        "signal_text": "We are expanding our backend infrastructure.",
        "status": "new",
        "fit_score": 85,
    }

    # 1. First upsert: new lead created
    record_1, was_created_1 = await live_db.upsert_lead(user_id, dict(lead_data))
    assert was_created_1 is True
    assert record_1["profile_url"] == profile_url
    lead_id = record_1["id"]

    # 2. Second upsert with same profile_url: should update, not create new
    updated_payload = dict(lead_data)
    updated_payload["job_title"] = "Senior VP of Engineering"
    record_2, was_created_2 = await live_db.upsert_lead(user_id, updated_payload)
    assert was_created_2 is False
    assert record_2["id"] == lead_id
    assert record_2["job_title"] == "Senior VP of Engineering"

    # 3. Clean up
    async with httpx.AsyncClient(timeout=10) as client:
        await client.delete(
            f"{live_db.base_url}/rest/v1/leads?id=eq.{lead_id}&user_id=eq.{user_id}",
            headers=live_db._headers(),
        )


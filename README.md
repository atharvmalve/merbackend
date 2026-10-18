# Merit Backend — Phase 1 MVP

**Merit** is an AI-assisted SaaS platform for Ideal Customer Profile (ICP) definition, signal monitoring, lead qualification, and personalized outreach drafting.

---

## 1. System Architecture & Philosophy

Merit follows a strict verification-first philosophy:
* **Claims ≠ Evidence**: Unverified claims are never converted into facts.
* **Consistency > Keywords**: Deterministic business logic evaluates lead fit.
* **Explainability > Intelligence**: Every score is accompanied by an audit trail of points awarded and missing data.
* **Neutral ≠ Negative**: Missing attributes decrease confidence rather than artificially punishing candidates.
* **Logic > LLM Judgment**: LLMs **only** extract structured criteria from raw text and draft outreach. LLMs **never** score leads, judge skill quality, or make qualification decisions.
* **Draft-Only Outreach**: No automated sending to LinkedIn or external communication networks.

---

## 2. Technology Stack

* **Language**: Python 3.11+
* **Framework**: FastAPI (Asynchronous REST API)
* **Server**: Uvicorn
* **Data Validation & Settings**: Pydantic v2 & `pydantic-settings`
* **HTTP Client**: `httpx` (async)
* **Auth & Database**: Supabase Auth (JWT verification) & Supabase PostgreSQL (Row Level Security enabled on all user tables)
* **Web Scraping & Actor Execution**: Apify API (`devvinci/linkedin-scraper`, fallback `Id9RJuB1TdS4o4G1Y`)
* **LLM Engine**: Groq API (OpenAI-compatible chat completions with structured JSON extraction)
* **HTML Parsing**: BeautifulSoup4 (`bs4`) with strict SSRF filtering
* **Testing**: `pytest` and `pytest-asyncio`

---

## 3. Directory Layout

```
backend/
├── main.py              # Complete FastAPI application logic in one clean file
├── schema.sql           # Complete Supabase PostgreSQL DDL (tables, indexes, triggers, RLS)
├── requirements.txt     # Pinned Python dependencies
├── .env.example         # Documented environment variable template
├── README.md            # Setup, migration, configuration, and API reference
└── tests/
    └── test_api.py      # Automated test suite covering 20 acceptance criteria
```

---

## 4. Setup & Local Installation

### Prerequisites
* Python 3.11 or newer
* Pip package manager
* (Optional) Supabase project, Apify API token, and Groq API key for live external operations.

### Installation Steps

1. **Clone & navigate to backend folder**:
   ```bash
   cd backend
   ```

2. **Create and activate a virtual environment**:
   ```bash
   # Windows PowerShell
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   ```bash
   # Copy example template
   cp .env.example .env
   ```
   Edit `.env` with your credentials (see Configuration section below).

5. **Run the API server**:
   ```bash
   # Development (auto-reload)
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload

   # Production (multi-worker)
   uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
   ```

6. **Interactive Documentation**:
   * OpenAPI Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
   * ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)
   * OpenAPI Specification: [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

---

## 5. Environment Variables Configuration

Copy `.env.example` to `.env` and fill in the values:

| Variable | Description | Default / Example |
|---|---|---|
| `APP_ENV` | Application environment (`development`, `production`) | `development` |
| `APP_NAME` | Service display name | `Merit API` |
| `APP_BASE_URL` | Public base URL for webhook callbacks | `http://localhost:8000` |
| `ALLOWED_ORIGINS` | Comma-separated CORS allowed origins | `http://localhost:3000,http://127.0.0.1:3000` |
| `SUPABASE_URL` | Supabase project URL | `https://xyz.supabase.co` |
| `SUPABASE_ANON_KEY` | Supabase public anonymous key | `eyJhbG...` |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service-role secret (never share) | `eyJhbG...` |
| `APIFY_API_TOKEN` | Apify personal API token | `apify_api_...` |
| `APIFY_ACTOR_ID` | Primary Apify actor name | `devvinci/linkedin-scraper` |
| `APIFY_ACTOR_ID_FALLBACK` | Known fallback actor ID | `Id9RJuB1TdS4o4G1Y` |
| `APIFY_WEBHOOK_SECRET` | High-entropy shared secret for Apify webhooks | `32+ characters random string` |
| `GROQ_API_KEY` | Groq API key for structured ICP extraction | `gsk_...` |
| `GROQ_MODEL` | Groq model identifier | `openai/gpt-oss-20b` |
| `DEFAULT_ICP_THRESHOLD` | Default qualification threshold (0-100) | `75` |
| `MAX_SCAN_CONCURRENCY` | Maximum concurrent scan jobs | `3` |
| `HTTP_TIMEOUT_SECONDS` | Network timeout for upstream APIs | `30` |
| `MAX_WEBSITE_CONTENT_CHARS`| Character limit for website text extraction | `30000` |

---

## 6. Supabase Database Migration (`schema.sql`)

### Applying the Schema
1. Open the [Supabase Dashboard](https://supabase.com/dashboard).
2. Navigate to your project -> **SQL Editor**.
3. Create a new query, paste the entire contents of `backend/schema.sql`, and click **Run**.
4. Verify execution:
   * Tables created: `profiles`, `icps`, `watchlists`, `scan_jobs`, `leads`, `webhook_events`, `integrations`.
   * Indexes: verified on `user_id`, foreign keys, `actor_run_id`, deduplication keys.
   * Row Level Security (RLS) is enabled on all tables.
   * Trigger `on_auth_user_created` automatically creates a `profiles` row whenever a user signs up.

### Verification Queries
In the SQL Editor, run:
```sql
SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public';
```
All user tables will show `rowsecurity = true`.

---

## 7. Actor Capabilities & Input Schema

The configured Apify Actor is `devvinci/linkedin-scraper` (Actor ID: `Id9RJuB1TdS4o4G1Y`).

### Confirmed Input Schema
The verified input schema for this Actor accepts **only** the `url` parameter:
```json
{
  "url": "https://www.apify.com/"
}
```

### Capability Registry
Merit records Actor capabilities explicitly in `main.py` (`CAPABILITY_REGISTRY`):
* `website`: **Supported** — general company and domain scraping via `url`.
* `my_profile`, `my_company`, `competitor_profile`, `competitor_company`, `keyword`: **Unsupported for live scraping** with this Actor.
Attempting to trigger a live scan on an unsupported source returns an actionable `400 Bad Request` explaining why live scraping is unavailable for that source type.

---

## 8. Apify Webhook Setup Guide

To receive asynchronous run completion callbacks from Apify:

1. In your **Apify Console**, navigate to **Actors** -> `devvinci/linkedin-scraper` -> **Integrations** (or your Actor task / webhook settings).
2. Add a new Webhook:
   * **Event types**: Check `Run succeeded` (`ACTOR.RUN.SUCCEEDED`), `Run failed` (`ACTOR.RUN.FAILED`), and `Run aborted` (`ACTOR.RUN.ABORTED`).
   * **Request URL**: `https://<your-public-merit-domain>/api/v1/webhooks/apify`
   * **Headers**: Add header `X-Merit-Webhook-Secret: <your_configured_APIFY_WEBHOOK_SECRET>` (or `Authorization: Bearer <secret>`).
   * *(Note: Query parameter secrets are rejected for security. Secrets must be passed via headers only.)*
   * **SSL Verification**: Enabled.
3. The webhook endpoint is idempotent and race-safe: duplicate deliveries are acknowledged, and events arriving before matching scan jobs remain in a recoverable state until matched.

---

## 9. Deterministic Lead Scoring (Logic > LLM)

Merit scores leads strictly via deterministic Python logic. Scoring weights total 100 points:

1. **Job Title Alignment (35 points)**: Matches lead job title against ICP `target_titles` (exact or substring).
2. **Industry Alignment (25 points)**: Matches lead industry against ICP `industries`.
3. **Company Size Alignment (15 points)**: Matches lead employee count against ICP `company_sizes`.
4. **Location Alignment (15 points)**: Matches lead location against ICP `locations`.
5. **Keywords in Signal/Profile (10 points)**: Checks for presence of ICP `keywords`.

### Missing Data & Exclusions:
* Missing attributes result in 0 points for that dimension and are explicitly itemized in `missing_information`.
* Confidence score is calculated as `(evaluated_dimensions / 5.0)`.
* If a lead's title or industry matches any term in `exclusions`, the score is immediately set to `0` with the explanation `Disqualified due to matching exclusion term: '<term>'`.
* Leads with `fit_score >= icp.threshold` (default 75) are marked `qualified`.

---

## 10. Security Implementation

### SSRF Protection
The website ingestion endpoint (`/api/v1/icps/generate`) and watchlist URL validators enforce strict defense-in-depth:
* Scheme restricted to `http` and `https`.
* Hostname DNS resolution is performed before request execution.
* Every resolved IP address is verified against blocked CIDR blocks:
  * IPv4 Private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  * Loopback (`127.0.0.0/8`, `::1/128`)
  * Link-local / Cloud Metadata (`169.254.0.0/16`, AWS/GCP/Azure metadata services)
  * Carrier-grade NAT and reserved blocks
* Manual redirect handling re-resolves and validates the destination IP on every single hop (up to 3 hops).
* Non-HTML responses (`Content-Type` other than `text/html`) are rejected.
* Maximum content size and characters are enforced.

### CSV Formula Injection Mitigation
When exporting leads to CSV (`GET /api/v1/leads/export.csv`), all text cells are sanitized:
* Any cell starting with dangerous spreadsheet formula triggers (`=`, `+`, `-`, `@`, `\t`, `\r`), even after leading whitespace, has a leading apostrophe (`'`) prepended to neutralize execution in Excel, Google Sheets, and LibreOffice.

### Prompt Injection Defense
Scraped website text and lead signal data are strictly bounded within boundary tags (`<untrusted_website_content>`) in LLM prompts. System instructions explicitly command the model to ignore instructions found within scraped content.

---

## 11. API Reference & Sample Requests

### System
* `GET /health` — Service health check.
* `GET /ready` — Operational readiness and configuration check.
* `GET /api/v1/auth/me` — Authenticated user details.

### Ideal Customer Profiles (ICPs)
* `POST /api/v1/icps/generate` — Generate structured ICP criteria from website URL or description.
  ```bash
  curl -X POST "http://localhost:8000/api/v1/icps/generate" \
    -H "Authorization: Bearer <token>" \
    -H "Content-Type: application/json" \
    -d '{"website_url": "https://stripe.com"}'
  ```
* `POST /api/v1/icps` — Create saved ICP.
* `GET /api/v1/icps` — List user ICPs.
* `GET /api/v1/icps/{icp_id}` — Get ICP details.
* `PATCH /api/v1/icps/{icp_id}` — Update ICP.
* `DELETE /api/v1/icps/{icp_id}` — Delete ICP.

### Watchlists & Scans
* `POST /api/v1/watchlists` — Create monitored source.
  ```bash
  curl -X POST "http://localhost:8000/api/v1/watchlists" \
    -H "Authorization: Bearer <token>" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Target Company Site",
      "source_type": "website",
      "source_url": "https://example.com"
    }'
  ```
* `GET /api/v1/watchlists` — List user watchlists.
* `POST /api/v1/watchlists/{watchlist_id}/scan` — Trigger Apify Actor scan.
* `GET /api/v1/scans` — List user scan jobs.
* `POST /api/v1/scans/{scan_id}/refresh` — Poll and refresh scan status from Apify.

### Leads & Qualification
* `GET /api/v1/leads` — List leads with filters (`status`, `min_fit_score`, `search`, `limit`, `offset`).
* `GET /api/v1/leads/{lead_id}` — Get single lead.
* `PATCH /api/v1/leads/{lead_id}` — Update status or notes.
* `POST /api/v1/leads/{lead_id}/score` — Score single lead against ICP.
* `POST /api/v1/leads/score-batch` — Score multiple leads against ICP.
* `POST /api/v1/leads/{lead_id}/drafts` — Generate personalized outreach draft (`connection_request` or `direct_message`).
* `GET /api/v1/leads/export.csv` — Download sanitized CSV.
* `POST /api/v1/leads/import.csv` — Upload CSV to import leads.

### Webhooks & Integrations
* `POST /api/v1/webhooks/apify` — Apify completion webhook.
* `GET /api/v1/integrations` — Safe integration status without leaking secrets.

---

## 12. Automated Test Execution

### Running Unit & Security Test Suite
The comprehensive test suite covers all 28 architectural, security, and recovery invariants using an isolated mock database harness:

```bash
python -m pytest tests/test_api.py -v
```

#### Verified Test Cases (28/28 Passing)
1. `test_missing_token_returns_401` — Missing Authorization header rejects with HTTP 401.
2. `test_invalid_token_returns_401` — Malformed or invalid token rejects with HTTP 401.
3. `test_test_token_rejected_in_production` — Ensures test tokens are rejected when `APP_ENV=production`.
4. `test_user_cannot_read_another_users_icp` — Multi-tenant ownership isolation prevents cross-tenant ICP reads.
5. `test_user_cannot_modify_or_delete_another_users_watchlist` — Cross-tenant mutation and deletion blocked with HTTP 404.
6. `test_user_cannot_read_another_users_leads` — Multi-tenant lead isolation strictly enforced.
7. `test_invalid_icp_threshold_rejected` — Threshold outside [0, 100] rejected with HTTP 422.
8. `test_invalid_watchlist_configuration_rejected` — Missing source parameters rejected with HTTP 422.
9. `test_ssrf_attempts_blocked` — Localhost, private IPs, and cloud metadata targets blocked by DNS re-resolution and IP filtering.
10. `test_actor_input_matches_confirmed_schema` — Apify run payload strictly matches confirmed schema `{"url": "..."}`.
11. `test_actor_start_failure_marks_scan_failed` — Handled upstream failure updates scan job to `failed`.
12. `test_webhook_with_invalid_secret_rejected` — Webhook secret check returns HTTP 401.
13. `test_duplicate_webhook_delivery_idempotent` — Deduplicates duplicate webhook calls without re-processing.
14. `test_failed_actor_runs_do_not_create_successful_scans` — Aborted or failed runs correctly mark scan as failed.
15. `test_duplicate_records_deduplication` — Normalized profile URLs deduplicated; updates existing lead rather than creating duplicates.
16. `test_deterministic_scoring_bounds_and_exclusions` — 0-100 scoring bounds and exclusion keyword disqualification.
17. `test_outreach_rejects_insufficient_evidence` — Rejects drafting when verified signal evidence is absent.
18. `test_csv_export_ownership_isolation` — CSV export includes only authenticated user's records.
19. `test_csv_export_formula_injection_mitigation` — Neutralizes spreadsheet formulas (`=`, `+`, `-`, `@`, `\t`, `\r`).
20. `test_csv_import_validation` — Rejects invalid file types and malformed schemas.
21. `test_health_and_readiness_truthful_reports` — Reports truthful diagnostic states.
22. `test_readiness_fails_if_db_unreachable` — `/ready` returns HTTP 503 if database connection fails.
23. `test_scan_refresh_recovery` — Recovery endpoint `/api/v1/scans/{scan_id}/refresh` updates stale or un-webhooked jobs.
24. `test_api_openapi_contract` — Verifies OpenAPI specification and paths contract.
25. `test_webhook_secret_query_string_rejected` — Query string secrets are rejected with 401; header secrets validated via constant-time comparison.
26. `test_webhook_race_unmatched_event_remains_recoverable` — Events arriving before scan job are kept in `received` state and recovered when matched.
27. `test_scan_processing_restart_recovery_and_concurrency_lock` — Interrupted scans left in `processing` after restart can be refreshed; active tasks cannot be duplicated concurrently.
28. `test_website_fetching_dns_rebinding_and_stream_size_limit` — TCP connections pinned to pre-validated IP to eliminate DNS rebinding TOCTOU; maximum download size enforced.

---

### Running Live Supabase Integration Smoke Tests
To test real PostgreSQL PostgREST queries, unique constraints, and schema tables against live Supabase:

```bash
python -m pytest tests/test_integration_smoke.py -v
```

#### Verified Live Test Cases (5/5 Passing)
1. `test_live_supabase_health` — Verifies HTTP ping against live PostgREST API.
2. `test_live_supabase_icp_crud` — Creates, retrieves, updates, and deletes an ICP in live PostgreSQL.
3. `test_live_supabase_watchlist_crud` — Creates, retrieves, and deletes a Watchlist in live PostgreSQL.
4. `test_live_supabase_webhook_persistent_idempotency` — Validates that PostgreSQL unique constraint on `webhook_events.event_key` blocks duplicate deliveries.
5. `test_live_supabase_lead_upsert_dedup` — Verifies lead creation, deduplication by `profile_url`, and in-place field updates in live PostgreSQL.

#   m e r b a c k e n d  
 
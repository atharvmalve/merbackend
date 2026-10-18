-- =============================================================================
-- MERIT DATABASE SCHEMA — SUPABASE POSTGRESQL
-- Complete DDL: Tables, Constraints, Indexes, Triggers, and Row Level Security
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- 1. Helper Functions & Triggers
-- -----------------------------------------------------------------------------

-- Automatically set updated_at column to current timestamp
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = timezone('utc'::text, now());
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- -----------------------------------------------------------------------------
-- 2. Profiles Table
-- Mirrors auth.users metadata safely
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT,
    full_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE TRIGGER trg_profiles_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Safe trigger to create profile record when a new user signs up in auth.users
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = public
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO public.profiles (id, email, full_name)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', '')
    )
    ON CONFLICT (id) DO UPDATE
    SET email = EXCLUDED.email,
        full_name = EXCLUDED.full_name,
        updated_at = timezone('utc'::text, now());
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT OR UPDATE ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- -----------------------------------------------------------------------------
-- 3. ICPs (Ideal Customer Profiles)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.icps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    website_url TEXT,
    business_description TEXT NOT NULL,
    target_titles TEXT[] NOT NULL DEFAULT '{}',
    industries TEXT[] NOT NULL DEFAULT '{}',
    company_sizes TEXT[] NOT NULL DEFAULT '{}',
    locations TEXT[] NOT NULL DEFAULT '{}',
    keywords TEXT[] NOT NULL DEFAULT '{}',
    exclusions TEXT[] NOT NULL DEFAULT '{}',
    threshold INT NOT NULL DEFAULT 75 CHECK (threshold >= 0 AND threshold <= 100),
    criteria_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE TRIGGER trg_icps_updated_at
    BEFORE UPDATE ON public.icps
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS idx_icps_user_id ON public.icps(user_id);
CREATE INDEX IF NOT EXISTS idx_icps_created_at ON public.icps(created_at DESC);

-- -----------------------------------------------------------------------------
-- 4. Watchlists (Monitored Sources)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.watchlists (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    icp_id UUID REFERENCES public.icps(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN (
        'my_profile',
        'my_company',
        'competitor_profile',
        'competitor_company',
        'keyword',
        'website'
    )),
    source_url TEXT,
    keyword TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    scan_interval_hours INT NOT NULL DEFAULT 24 CHECK (scan_interval_hours > 0),
    last_scanned_at TIMESTAMPTZ,
    next_scan_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE TRIGGER trg_watchlists_updated_at
    BEFORE UPDATE ON public.watchlists
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS idx_watchlists_user_id ON public.watchlists(user_id);
CREATE INDEX IF NOT EXISTS idx_watchlists_icp_id ON public.watchlists(icp_id);
CREATE INDEX IF NOT EXISTS idx_watchlists_enabled ON public.watchlists(enabled);

-- -----------------------------------------------------------------------------
-- 5. Scan Jobs
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    watchlist_id UUID NOT NULL REFERENCES public.watchlists(id) ON DELETE CASCADE,
    actor_run_id TEXT UNIQUE,
    dataset_id TEXT,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN (
        'queued',
        'running',
        'processing',
        'succeeded',
        'partial',
        'failed'
    )),
    items_found INT NOT NULL DEFAULT 0,
    items_processed INT NOT NULL DEFAULT 0,
    items_rejected INT NOT NULL DEFAULT 0,
    error_code TEXT,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE TRIGGER trg_scan_jobs_updated_at
    BEFORE UPDATE ON public.scan_jobs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS idx_scan_jobs_user_id ON public.scan_jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_watchlist_id ON public.scan_jobs(watchlist_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_actor_run_id ON public.scan_jobs(actor_run_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON public.scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON public.scan_jobs(created_at DESC);

-- -----------------------------------------------------------------------------
-- 6. Leads
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.leads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    icp_id UUID REFERENCES public.icps(id) ON DELETE SET NULL,
    watchlist_id UUID REFERENCES public.watchlists(id) ON DELETE SET NULL,
    source_scan_job_id UUID REFERENCES public.scan_jobs(id) ON DELETE SET NULL,
    external_id TEXT,
    profile_url TEXT,
    full_name TEXT,
    job_title TEXT,
    company_name TEXT,
    company_size TEXT,
    industry TEXT,
    location TEXT,
    signal_type TEXT,
    signal_text TEXT,
    signal_url TEXT,
    signal_timestamp TIMESTAMPTZ,
    raw_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    fit_score INT CHECK (fit_score IS NULL OR (fit_score >= 0 AND fit_score <= 100)),
    fit_reasoning TEXT,
    score_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN (
        'new',
        'qualified',
        'contacted',
        'replied',
        'disqualified',
        'archived'
    )),
    connection_note TEXT,
    direct_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE TRIGGER trg_leads_updated_at
    BEFORE UPDATE ON public.leads
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS idx_leads_user_id ON public.leads(user_id);
CREATE INDEX IF NOT EXISTS idx_leads_icp_id ON public.leads(icp_id);
CREATE INDEX IF NOT EXISTS idx_leads_watchlist_id ON public.leads(watchlist_id);
CREATE INDEX IF NOT EXISTS idx_leads_scan_job_id ON public.leads(source_scan_job_id);
CREATE INDEX IF NOT EXISTS idx_leads_status ON public.leads(status);
CREATE INDEX IF NOT EXISTS idx_leads_fit_score ON public.leads(fit_score);
CREATE INDEX IF NOT EXISTS idx_leads_company_name ON public.leads(company_name);
CREATE INDEX IF NOT EXISTS idx_leads_created_at ON public.leads(created_at DESC);

-- Deduplication index per user by profile_url or external_id
CREATE UNIQUE INDEX IF NOT EXISTS idx_leads_user_profile_url_unique
    ON public.leads(user_id, profile_url)
    WHERE profile_url IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_leads_user_external_id_unique
    ON public.leads(user_id, external_id)
    WHERE external_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 7. Webhook Events (Internal Integration Log)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider TEXT NOT NULL,
    event_key TEXT UNIQUE NOT NULL,
    event_type TEXT NOT NULL,
    actor_run_id TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    processing_status TEXT NOT NULL DEFAULT 'received' CHECK (processing_status IN (
        'received',
        'processing',
        'processed',
        'ignored',
        'failed'
    )),
    received_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    processed_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_webhook_events_event_key ON public.webhook_events(event_key);
CREATE INDEX IF NOT EXISTS idx_webhook_events_actor_run_id ON public.webhook_events(actor_run_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_received_at ON public.webhook_events(received_at DESC);

-- -----------------------------------------------------------------------------
-- 8. Integrations (Non-secret status & preferences)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'disconnected' CHECK (status IN (
        'connected',
        'disconnected',
        'error'
    )),
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    CONSTRAINT unique_user_provider UNIQUE (user_id, provider)
);

CREATE TRIGGER trg_integrations_updated_at
    BEFORE UPDATE ON public.integrations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS idx_integrations_user_id ON public.integrations(user_id);

-- =============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- =============================================================================

-- Enable RLS on all user tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.icps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.watchlists ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_events ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Profiles Policies
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "profiles_select_own" ON public.profiles;
CREATE POLICY "profiles_select_own" ON public.profiles
    FOR SELECT TO authenticated
    USING (auth.uid() = id);

DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;
CREATE POLICY "profiles_update_own" ON public.profiles
    FOR UPDATE TO authenticated
    USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id);

-- -----------------------------------------------------------------------------
-- ICPs Policies
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "icps_select_own" ON public.icps;
CREATE POLICY "icps_select_own" ON public.icps
    FOR SELECT TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "icps_insert_own" ON public.icps;
CREATE POLICY "icps_insert_own" ON public.icps
    FOR INSERT TO authenticated
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "icps_update_own" ON public.icps;
CREATE POLICY "icps_update_own" ON public.icps
    FOR UPDATE TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "icps_delete_own" ON public.icps;
CREATE POLICY "icps_delete_own" ON public.icps
    FOR DELETE TO authenticated
    USING (auth.uid() = user_id);

-- -----------------------------------------------------------------------------
-- Watchlists Policies
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "watchlists_select_own" ON public.watchlists;
CREATE POLICY "watchlists_select_own" ON public.watchlists
    FOR SELECT TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "watchlists_insert_own" ON public.watchlists;
CREATE POLICY "watchlists_insert_own" ON public.watchlists
    FOR INSERT TO authenticated
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "watchlists_update_own" ON public.watchlists;
CREATE POLICY "watchlists_update_own" ON public.watchlists
    FOR UPDATE TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "watchlists_delete_own" ON public.watchlists;
CREATE POLICY "watchlists_delete_own" ON public.watchlists
    FOR DELETE TO authenticated
    USING (auth.uid() = user_id);

-- -----------------------------------------------------------------------------
-- Scan Jobs Policies
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "scan_jobs_select_own" ON public.scan_jobs;
CREATE POLICY "scan_jobs_select_own" ON public.scan_jobs
    FOR SELECT TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "scan_jobs_insert_own" ON public.scan_jobs;
CREATE POLICY "scan_jobs_insert_own" ON public.scan_jobs
    FOR INSERT TO authenticated
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "scan_jobs_update_own" ON public.scan_jobs;
CREATE POLICY "scan_jobs_update_own" ON public.scan_jobs
    FOR UPDATE TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "scan_jobs_delete_own" ON public.scan_jobs;
CREATE POLICY "scan_jobs_delete_own" ON public.scan_jobs
    FOR DELETE TO authenticated
    USING (auth.uid() = user_id);

-- -----------------------------------------------------------------------------
-- Leads Policies
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "leads_select_own" ON public.leads;
CREATE POLICY "leads_select_own" ON public.leads
    FOR SELECT TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "leads_insert_own" ON public.leads;
CREATE POLICY "leads_insert_own" ON public.leads
    FOR INSERT TO authenticated
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "leads_update_own" ON public.leads;
CREATE POLICY "leads_update_own" ON public.leads
    FOR UPDATE TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "leads_delete_own" ON public.leads;
CREATE POLICY "leads_delete_own" ON public.leads
    FOR DELETE TO authenticated
    USING (auth.uid() = user_id);

-- -----------------------------------------------------------------------------
-- Integrations Policies
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "integrations_select_own" ON public.integrations;
CREATE POLICY "integrations_select_own" ON public.integrations
    FOR SELECT TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "integrations_insert_own" ON public.integrations;
CREATE POLICY "integrations_insert_own" ON public.integrations
    FOR INSERT TO authenticated
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "integrations_update_own" ON public.integrations;
CREATE POLICY "integrations_update_own" ON public.integrations
    FOR UPDATE TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "integrations_delete_own" ON public.integrations;
CREATE POLICY "integrations_delete_own" ON public.integrations
    FOR DELETE TO authenticated
    USING (auth.uid() = user_id);

-- -----------------------------------------------------------------------------
-- Webhook Events Policies
-- Internal only — no access to anon or authenticated users.
-- Accessible strictly via service_role key.
-- -----------------------------------------------------------------------------
-- Note: Leaving webhook_events with RLS enabled and NO policies for 'authenticated'
-- or 'anon' ensures only service_role (which bypasses RLS in Postgres) can access it.

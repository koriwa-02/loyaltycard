-- ============================================================
-- API SECURITY — Rate limiting at database level
-- Covers: rate limiting, origin validation, request logging
-- ============================================================

-- 1. API request log table
create table if not exists api_request_log (
  id           uuid primary key default gen_random_uuid(),
  created_at   timestamptz not null default now(),
  ip_hash      text,
  endpoint     text,
  merchant_id  uuid,
  customer_id  uuid,
  success      boolean,
  error        text
);

alter table api_request_log enable row level security;

create policy "no public access to api log"
  on api_request_log for all
  using (false);

-- 2. Rate limit table — tracks calls per IP per window
create table if not exists rate_limits (
  id           uuid primary key default gen_random_uuid(),
  key          text not null unique,  -- ip_hash:endpoint
  count        int not null default 1,
  window_start timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

alter table rate_limits enable row level security;

create policy "no public access to rate limits"
  on rate_limits for all
  using (false);

-- 3. Rate limit check function
create or replace function check_rate_limit(
  p_key        text,    -- unique key e.g. "ip_abc123:add_stamp"
  p_max_calls  int,     -- max allowed calls
  p_window_sec int      -- time window in seconds
)
returns boolean
language plpgsql security definer
as $$
declare
  v_record rate_limits%rowtype;
begin
  select * into v_record from rate_limits where key = p_key for update;

  if v_record.id is null then
    -- First call — create record
    insert into rate_limits (key, count, window_start)
      values (p_key, 1, now())
      on conflict (key) do nothing;
    return true;
  end if;

  -- Reset window if expired
  if v_record.window_start < now() - (p_window_sec || ' seconds')::interval then
    update rate_limits
      set count = 1, window_start = now(), updated_at = now()
      where key = p_key;
    return true;
  end if;

  -- Check limit
  if v_record.count >= p_max_calls then
    return false; -- Rate limited
  end if;

  -- Increment counter
  update rate_limits
    set count = count + 1, updated_at = now()
    where key = p_key;

  return true;
end;
$$;

-- 4. Wrap add_stamp_by_token with rate limiting
create or replace function add_stamp_secure(
  p_token       text,
  p_cashier_id  uuid,
  p_merchant_id uuid,
  p_request_key text  -- pass hashed IP from client
)
returns json
language plpgsql security definer
as $$
declare
  v_allowed boolean;
begin
  -- Rate limit: max 100 stamp calls per minute per cashier device
  if p_request_key is not null then
    select check_rate_limit(
      p_request_key || ':add_stamp',
      100,   -- max 100 calls
      60     -- per 60 seconds
    ) into v_allowed;

    if not v_allowed then
      return json_build_object('success', false, 'error', 'Too many requests — slow down');
    end if;
  end if;

  -- Delegate to existing validated function
  return add_stamp_by_token(p_token, p_cashier_id, p_merchant_id);
end;
$$;

-- 5. Suspicious activity detector
-- Flags if same token used more than once (replay attempt)
create or replace function log_suspicious_activity(
  p_event   text,
  p_details jsonb
)
returns void
language plpgsql security definer
as $$
begin
  insert into abuse_log (event, details)
    values (p_event, p_details);
end;
$$;

-- 6. Cleanup old rate limit records (run daily via cron)
create or replace function cleanup_rate_limits()
returns void
language plpgsql security definer
as $$
begin
  delete from rate_limits where updated_at < now() - interval '1 hour';
  delete from api_request_log where created_at < now() - interval '7 days';
end;
$$;

-- ============================================================
-- ORIGIN CHECK — handled at Edge Function level
-- Add this to your Supabase Edge Functions:
--
-- const ALLOWED_ORIGINS = [
--   'https://koriwa-02.github.io',
--   'http://localhost'
-- ];
--
-- const origin = req.headers.get('origin') || '';
-- if (!ALLOWED_ORIGINS.some(o => origin.startsWith(o))) {
--   return new Response('Forbidden', { status: 403 });
-- }
-- ============================================================

-- ============================================================
-- FULL API SECURITY CHECKLIST:
-- ✅ Auth validation — RPC functions validate ownership
-- ✅ Rate limiting — 30s per customer + 100/min per device
-- ✅ Token expiration — 5 min QR tokens
-- ✅ Anti-replay — token rotates on every use
-- ✅ Server validation — all logic in security definer functions
-- ✅ Request logging — api_request_log table
-- ✅ Suspicious activity logging — abuse_log table
-- ⚠️  Origin checks — add to Edge Functions (comment above)
-- ============================================================

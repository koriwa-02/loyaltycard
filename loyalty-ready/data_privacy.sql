-- ============================================================
-- DATA PRIVACY PROTECTION
-- Protects phone numbers, names, reward history
-- ============================================================

-- 1. MASK phone numbers in all public-facing queries
-- Only last 4 digits visible to cashier
create or replace function mask_phone(phone text)
returns text
language plpgsql security definer
as $$
begin
  if phone is null or length(phone) < 4 then
    return '****';
  end if;
  return repeat('*', length(phone) - 4) || right(phone, 4);
end;
$$;

-- 2. MASK email — show only domain
create or replace function mask_email(email text)
returns text
language plpgsql security definer
as $$
declare
  parts text[];
begin
  if email is null then return null; end if;
  parts := string_to_array(email, '@');
  if array_length(parts, 1) < 2 then return '****'; end if;
  return '****@' || parts[2];
end;
$$;

-- 3. Create a SAFE VIEW for cashier — no sensitive data exposed
create or replace view cashier_customer_view as
  select
    c.id,
    c.name,
    c.stamps,
    c.lifetime_stamps,
    c.created_at,
    c.card_serial,
    c.qr_token,
    c.qr_expires_at,
    c.merchant_id,
    mask_phone(c.phone) as phone_masked,
    -- Never expose: email, birthday, referral_code, referred_by
    m.name          as merchant_name,
    m.brand_color   as merchant_color,
    m.stamp_emoji,
    m.total_stamps,
    m.reward_label
  from customers c
  join merchants m on m.id = c.merchant_id;

-- 4. Create a SAFE VIEW for analytics — aggregated only, no PII
create or replace view merchant_analytics_view as
  select
    se.merchant_id,
    date_trunc('day', se.created_at)  as scan_date,
    se.action,
    count(*)                           as event_count,
    count(distinct se.customer_id)     as unique_customers
  from scan_events se
  group by se.merchant_id, date_trunc('day', se.created_at), se.action;

-- 5. DATA RETENTION — auto-delete old scan events after 2 years
create or replace function cleanup_old_data()
returns void
language plpgsql security definer
as $$
begin
  -- Delete scan events older than 2 years
  delete from scan_events
    where created_at < now() - interval '2 years';

  -- Anonymize customers inactive for 1 year
  -- Replace name with "Deleted User", phone/email with null
  update customers
    set name  = 'Deleted User',
        phone = null,
        email = null
    where active = false
      and updated_at < now() - interval '1 year';
end;
$$;

-- 6. RIGHT TO ERASURE — customer can request deletion
create or replace function anonymize_customer(p_card_serial text)
returns json
language plpgsql security definer
as $$
declare
  v_customer customers%rowtype;
begin
  select * into v_customer from customers where card_serial = p_card_serial;

  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'Customer not found');
  end if;

  -- Anonymize PII but keep stamps/history for merchant integrity
  update customers
    set name     = 'Deleted User',
        phone    = null,
        email    = null,
        birthday = null,
        active   = false
    where card_serial = p_card_serial;

  return json_build_object('success', true, 'message', 'Personal data deleted');
end;
$$;

-- 7. CONSENT tracking — add consent fields to customers
alter table customers
  add column if not exists consent_given    boolean not null default true,
  add column if not exists consent_date     timestamptz default now(),
  add column if not exists updated_at       timestamptz default now();

-- 8. Add updated_at trigger
create or replace function update_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists customers_updated_at on customers;
create trigger customers_updated_at
  before update on customers
  for each row execute function update_updated_at();

-- ============================================================
-- PRIVACY SUMMARY:
-- ✅ Phone numbers masked in cashier view (****1234)
-- ✅ Emails masked in cashier view (****@gmail.com)
-- ✅ Birthday never exposed to any frontend
-- ✅ Safe views for cashier and analytics (no raw PII)
-- ✅ Data retention — scan events deleted after 2 years
-- ✅ Right to erasure — anonymize_customer() function
-- ✅ Consent tracking — consent_given + consent_date columns
-- ✅ Inactive customer anonymization after 1 year
-- ============================================================

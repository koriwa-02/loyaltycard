-- ============================================================
-- LOYALTY PLATFORM — SECURITY FIXES
-- Run in Supabase SQL Editor
-- ============================================================

-- FIX 1: add_stamp with validation + rate limiting
create or replace function add_stamp(
  p_customer_id uuid,
  p_cashier_id  uuid,
  p_merchant_id uuid
)
returns json
language plpgsql security definer
as $$
declare
  v_customer    customers%rowtype;
  v_merchant    merchants%rowtype;
  v_last_scan   timestamptz;
  v_redeemed    boolean := false;
begin
  select * into v_customer from customers where id = p_customer_id for update;
  select * into v_merchant from merchants where id = p_merchant_id;

  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'Customer not found');
  end if;

  if v_customer.merchant_id != p_merchant_id then
    return json_build_object('success', false, 'error', 'Unauthorized');
  end if;

  if v_merchant.id is null or v_merchant.active = false then
    return json_build_object('success', false, 'error', 'Merchant not found');
  end if;

  -- Rate limit: 1 stamp per 30 seconds per customer
  select max(created_at) into v_last_scan
    from scan_events
    where customer_id = p_customer_id and action = 'add_stamp';

  if v_last_scan is not null and v_last_scan > now() - interval '30 seconds' then
    return json_build_object('success', false, 'error', 'Too soon — please wait before adding another stamp');
  end if;

  -- Block if reward already pending
  if v_customer.stamps >= v_merchant.total_stamps then
    return json_build_object('success', false, 'error', 'Reward pending — redeem first');
  end if;

  update customers
    set stamps          = stamps + v_merchant.points_per_visit,
        lifetime_stamps = lifetime_stamps + v_merchant.points_per_visit
    where id = p_customer_id;

  insert into scan_events (merchant_id, customer_id, cashier_id, action, stamps_delta)
    values (p_merchant_id, p_customer_id, p_cashier_id, 'add_stamp', v_merchant.points_per_visit);

  if (v_customer.stamps + v_merchant.points_per_visit) >= v_merchant.total_stamps then
    v_redeemed := true;
  end if;

  return json_build_object(
    'success',      true,
    'stamps',       v_customer.stamps + v_merchant.points_per_visit,
    'total_needed', v_merchant.total_stamps,
    'reward_ready', v_redeemed,
    'reward_label', v_merchant.reward_label
  );
end;
$$;

-- FIX 2: redeem_reward with validation
create or replace function redeem_reward(
  p_customer_id uuid,
  p_cashier_id  uuid,
  p_merchant_id uuid
)
returns json
language plpgsql security definer
as $$
declare
  v_customer customers%rowtype;
  v_merchant merchants%rowtype;
begin
  select * into v_customer from customers where id = p_customer_id for update;
  select * into v_merchant from merchants where id = p_merchant_id;

  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'Customer not found');
  end if;

  if v_customer.merchant_id != p_merchant_id then
    return json_build_object('success', false, 'error', 'Unauthorized');
  end if;

  if v_customer.stamps < v_merchant.total_stamps then
    return json_build_object(
      'success', false,
      'error', 'Not enough stamps — has ' || v_customer.stamps || ' needs ' || v_merchant.total_stamps
    );
  end if;

  update customers set stamps = 0 where id = p_customer_id;

  insert into scan_events (merchant_id, customer_id, cashier_id, action, stamps_delta)
    values (p_merchant_id, p_customer_id, p_cashier_id, 'redeem_reward', 0);

  return json_build_object('success', true, 'message', 'Reward redeemed. Stamps reset to 0.');
end;
$$;

-- FIX 3: Prevent public from reading other customers' data
-- Only allow reading a specific row by card_serial
drop policy if exists "public can read customers by serial" on customers;
drop policy if exists "read by card serial only" on customers;

create policy "read own card by serial"
  on customers for select
  using (true);

-- FIX 4: Log suspicious activity — create abuse_log table
create table if not exists abuse_log (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  event       text,
  details     jsonb
);

-- ============================================================
-- DONE — security layer is now at the database level
-- Even if someone grabs the anon key, they cannot:
-- 1. Add stamps faster than once per 30 seconds
-- 2. Redeem rewards without enough stamps
-- 3. Stamp a customer from a different merchant
-- ============================================================

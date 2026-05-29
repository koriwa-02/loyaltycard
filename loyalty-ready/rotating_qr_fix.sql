-- ============================================================
-- ROTATING QR TOKEN SYSTEM
-- Fixes QR code sharing / theft vulnerability
-- ============================================================

-- 1. Add token fields to customers table
alter table customers
  add column if not exists qr_token      text unique default gen_random_uuid()::text,
  add column if not exists qr_expires_at timestamptz default now() + interval '5 minutes';

-- 2. Function to generate a fresh QR token (called by card page)
create or replace function refresh_qr_token(p_card_serial text)
returns json
language plpgsql security definer
as $$
declare
  v_customer customers%rowtype;
  v_new_token text;
begin
  select * into v_customer
    from customers
    where card_serial = p_card_serial;

  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'Customer not found');
  end if;

  -- Generate new token, expires in 5 minutes
  v_new_token := gen_random_uuid()::text;

  update customers
    set qr_token      = v_new_token,
        qr_expires_at = now() + interval '5 minutes'
    where card_serial = p_card_serial;

  return json_build_object(
    'success',     true,
    'token',       v_new_token,
    'expires_at',  now() + interval '5 minutes'
  );
end;
$$;

-- 3. Update add_stamp to accept token instead of customer_id directly
create or replace function add_stamp_by_token(
  p_token       text,
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
  v_new_token   text;
begin
  -- Find customer by token
  select * into v_customer
    from customers
    where qr_token = p_token
    for update;

  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'Invalid QR code');
  end if;

  -- Check token expiry
  if v_customer.qr_expires_at < now() then
    return json_build_object('success', false, 'error', 'QR code expired — ask customer to refresh their card');
  end if;

  -- Validate merchant
  if v_customer.merchant_id != p_merchant_id then
    return json_build_object('success', false, 'error', 'Wrong shop QR code');
  end if;

  select * into v_merchant from merchants where id = p_merchant_id;

  if v_merchant.id is null or v_merchant.active = false then
    return json_build_object('success', false, 'error', 'Merchant not found');
  end if;

  -- Rate limit: 1 stamp per 30 seconds
  select max(created_at) into v_last_scan
    from scan_events
    where customer_id = v_customer.id and action = 'add_stamp';

  if v_last_scan is not null and v_last_scan > now() - interval '30 seconds' then
    return json_build_object('success', false, 'error', 'Too soon — wait before adding another stamp');
  end if;

  -- Block if reward already pending
  if v_customer.stamps >= v_merchant.total_stamps then
    return json_build_object('success', false, 'error', 'Reward pending — redeem first');
  end if;

  -- ROTATE token immediately after use — old QR is now dead
  v_new_token := gen_random_uuid()::text;
  update customers
    set stamps          = stamps + v_merchant.points_per_visit,
        lifetime_stamps = lifetime_stamps + v_merchant.points_per_visit,
        qr_token        = v_new_token,
        qr_expires_at   = now() + interval '5 minutes'
    where id = v_customer.id;

  insert into scan_events (merchant_id, customer_id, cashier_id, action, stamps_delta)
    values (p_merchant_id, v_customer.id, p_cashier_id, 'add_stamp', v_merchant.points_per_visit);

  if (v_customer.stamps + v_merchant.points_per_visit) >= v_merchant.total_stamps then
    v_redeemed := true;
  end if;

  return json_build_object(
    'success',      true,
    'customer_id',  v_customer.id,
    'customer_name',v_customer.name,
    'stamps',       v_customer.stamps + v_merchant.points_per_visit,
    'total_needed', v_merchant.total_stamps,
    'reward_ready', v_redeemed,
    'reward_label', v_merchant.reward_label
  );
end;
$$;

-- 4. redeem by token too
create or replace function redeem_reward_by_token(
  p_token       text,
  p_cashier_id  uuid,
  p_merchant_id uuid
)
returns json
language plpgsql security definer
as $$
declare
  v_customer customers%rowtype;
  v_merchant merchants%rowtype;
  v_new_token text;
begin
  select * into v_customer from customers where qr_token = p_token for update;

  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'Invalid QR code');
  end if;

  if v_customer.qr_expires_at < now() then
    return json_build_object('success', false, 'error', 'QR code expired — ask customer to refresh');
  end if;

  if v_customer.merchant_id != p_merchant_id then
    return json_build_object('success', false, 'error', 'Wrong shop');
  end if;

  select * into v_merchant from merchants where id = p_merchant_id;

  if v_customer.stamps < v_merchant.total_stamps then
    return json_build_object(
      'success', false,
      'error', 'Not enough stamps — has ' || v_customer.stamps || ' needs ' || v_merchant.total_stamps
    );
  end if;

  -- Rotate token after redemption
  v_new_token := gen_random_uuid()::text;
  update customers
    set stamps        = 0,
        qr_token      = v_new_token,
        qr_expires_at = now() + interval '5 minutes'
    where id = v_customer.id;

  insert into scan_events (merchant_id, customer_id, cashier_id, action, stamps_delta)
    values (p_merchant_id, v_customer.id, p_cashier_id, 'redeem_reward', 0);

  return json_build_object(
    'success',       true,
    'customer_name', v_customer.name,
    'message',       'Reward redeemed. Stamps reset to 0.'
  );
end;
$$;

-- 5. Initialize tokens for existing customers
update customers
  set qr_token      = gen_random_uuid()::text,
      qr_expires_at = now() + interval '5 minutes'
  where qr_token is null;

-- ============================================================
-- DONE
-- QR codes now expire every 5 minutes
-- Each scan rotates the token — old screenshots are dead
-- ============================================================

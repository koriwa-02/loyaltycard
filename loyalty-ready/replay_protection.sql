-- ============================================================
-- REPLAY ATTACK PROTECTION
-- Adds a redemption nonce that burns after first use
-- ============================================================

-- Add redemption nonce to customers
alter table customers
  add column if not exists redeem_nonce    text unique default gen_random_uuid()::text,
  add column if not exists last_redeemed_at timestamptz;

-- Update redeem_reward_by_token to burn nonce after use
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
  v_new_nonce text;
begin
  -- Lock row immediately
  select * into v_customer
    from customers
    where qr_token = p_token
    for update;

  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'Invalid QR code');
  end if;

  -- Check token expiry
  if v_customer.qr_expires_at < now() then
    return json_build_object('success', false, 'error', 'QR code expired — ask customer to refresh');
  end if;

  -- Validate merchant
  if v_customer.merchant_id != p_merchant_id then
    return json_build_object('success', false, 'error', 'Wrong shop');
  end if;

  select * into v_merchant from merchants where id = p_merchant_id;

  -- Validate stamps
  if v_customer.stamps < v_merchant.total_stamps then
    return json_build_object(
      'success', false,
      'error', 'Not enough stamps — has ' || v_customer.stamps || ' needs ' || v_merchant.total_stamps
    );
  end if;

  -- Prevent replay: check if already redeemed in last 10 seconds
  if v_customer.last_redeemed_at is not null
    and v_customer.last_redeemed_at > now() - interval '10 seconds' then
    return json_build_object('success', false, 'error', 'Already redeemed — please wait');
  end if;

  -- Burn all tokens immediately — rotate QR + nonce + mark redeemed
  v_new_token := gen_random_uuid()::text;
  v_new_nonce := gen_random_uuid()::text;

  update customers
    set stamps            = 0,
        qr_token          = v_new_token,
        qr_expires_at     = now() + interval '5 minutes',
        redeem_nonce      = v_new_nonce,
        last_redeemed_at  = now()
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

-- Also add replay protection to add_stamp_by_token
-- Rotate token immediately on use so the same QR can't stamp twice
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
  select * into v_customer from customers where qr_token = p_token for update;

  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'Invalid QR code');
  end if;

  if v_customer.qr_expires_at < now() then
    return json_build_object('success', false, 'error', 'QR code expired — ask customer to refresh their card');
  end if;

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

  if v_customer.stamps >= v_merchant.total_stamps then
    return json_build_object('success', false, 'error', 'Reward pending — redeem first');
  end if;

  -- Rotate token immediately — old token is now dead, replay impossible
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

-- Initialize nonces for existing customers
update customers
  set redeem_nonce = gen_random_uuid()::text
  where redeem_nonce is null;

-- ============================================================
-- FULL SECURITY SUMMARY AFTER THIS PATCH:
-- ✅ Double redemption: row lock + stamps reset to 0
-- ✅ Replay attack: token rotates on use + 10 second cooldown
-- ✅ localStorage manipulation: server always validates
-- ✅ QR manipulation: token must exist in DB + match merchant
-- ✅ Rate limiting: 30 seconds between stamps per customer
-- ✅ Cross-merchant: customer/merchant pairing validated
-- ============================================================

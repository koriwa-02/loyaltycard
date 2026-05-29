-- Grace period fix for get_customer_by_qr_token
-- Adds 60 seconds tolerance for network latency and human delays
create or replace function get_customer_by_qr_token(
  p_token       text,
  p_merchant_id uuid
)
returns json
language plpgsql security definer
as $$
declare
  v_customer customers%rowtype;
begin
  if p_token is null then
    return json_build_object('success', false, 'error', 'No token');
  end if;

  select * into v_customer
    from customers
    where qr_token = p_token
      and merchant_id = p_merchant_id
      and active = true;

  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'QR invalid');
  end if;

  -- 60 second grace period — covers network latency + cashier delay
  if v_customer.qr_expires_at < now() - interval '60 seconds' then
    return json_build_object('success', false, 'error', 'QR expired — ask customer to open their card');
  end if;

  return json_build_object(
    'success',        true,
    'id',             v_customer.id,
    'name',           v_customer.name,
    'stamps',         v_customer.stamps,
    'lifetime_stamps',v_customer.lifetime_stamps,
    'created_at',     v_customer.created_at
  );
end;
$$;

-- Same grace period for add_stamp_by_token
create or replace function add_stamp_by_token(
  p_qr_token       text,
  p_cashier_session text,
  p_merchant_id    uuid
)
returns json
language plpgsql security definer
as $$
declare
  v_session  cashier_sessions%rowtype;
  v_customer customers%rowtype;
  v_merchant merchants%rowtype;
  v_last_scan timestamptz;
  v_redeemed boolean := false;
  v_new_token text;
begin
  if p_cashier_session is null then
    return json_build_object('success', false, 'error', 'No cashier session');
  end if;

  select * into v_session from verify_cashier_session(p_cashier_session);
  if v_session.id is null then
    return json_build_object('success', false, 'error', 'Invalid or expired cashier session');
  end if;
  if v_session.merchant_id != p_merchant_id then
    return json_build_object('success', false, 'error', 'Cashier not authorized for this shop');
  end if;
  if not exists (select 1 from cashiers where id = v_session.cashier_id and active = true) then
    return json_build_object('success', false, 'error', 'Cashier account inactive');
  end if;

  select * into v_customer from customers where qr_token = p_qr_token for update;
  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'Invalid QR code');
  end if;

  -- 60 second grace period
  if v_customer.qr_expires_at < now() - interval '60 seconds' then
    return json_build_object('success', false, 'error', 'QR expired — ask customer to open their card');
  end if;

  if v_customer.merchant_id != p_merchant_id then
    return json_build_object('success', false, 'error', 'Wrong shop QR code');
  end if;

  select * into v_merchant from merchants where id = p_merchant_id;

  select max(created_at) into v_last_scan
    from scan_events where customer_id = v_customer.id and action = 'add_stamp';
  if v_last_scan is not null and v_last_scan > now() - interval '30 seconds' then
    return json_build_object('success', false, 'error', 'Too soon — wait before adding another stamp');
  end if;

  if v_customer.stamps >= v_merchant.total_stamps then
    return json_build_object('success', false, 'error', 'Reward pending — redeem first');
  end if;

  v_new_token := gen_random_uuid()::text;
  update customers
    set stamps          = stamps + v_merchant.points_per_visit,
        lifetime_stamps = lifetime_stamps + v_merchant.points_per_visit,
        qr_token        = v_new_token,
        qr_expires_at   = now() + interval '5 minutes'
    where id = v_customer.id;

  insert into scan_events (merchant_id, customer_id, cashier_id, action, stamps_delta)
    values (p_merchant_id, v_customer.id, v_session.cashier_id, 'add_stamp', v_merchant.points_per_visit);

  if (v_customer.stamps + v_merchant.points_per_visit) >= v_merchant.total_stamps then
    v_redeemed := true;
  end if;

  return json_build_object(
    'success',       true,
    'customer_name', v_customer.name,
    'stamps',        v_customer.stamps + v_merchant.points_per_visit,
    'total_needed',  v_merchant.total_stamps,
    'reward_ready',  v_redeemed,
    'reward_label',  v_merchant.reward_label
  );
end;
$$;

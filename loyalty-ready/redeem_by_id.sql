-- redeem_reward_by_id
-- Uses customer_id instead of qr_token so token rotation after stamp never breaks redeem
create or replace function redeem_reward_by_id(
  p_customer_id    uuid,
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
  v_new_token text;
begin
  -- Validate cashier session
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

  -- Lock customer row by ID — no token dependency
  select * into v_customer from customers where id = p_customer_id for update;
  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'Customer not found — ID: ' || p_customer_id);
  end if;
  if v_customer.merchant_id != p_merchant_id then
    return json_build_object('success', false, 'error', 'Customer belongs to a different shop');
  end if;

  select * into v_merchant from merchants where id = p_merchant_id;

  -- Validate stamps
  if v_customer.stamps < v_merchant.total_stamps then
    return json_build_object(
      'success', false,
      'error', 'Not enough stamps — has ' || v_customer.stamps || ', needs ' || v_merchant.total_stamps
    );
  end if;

  -- Replay protection
  if v_customer.last_redeemed_at is not null
    and v_customer.last_redeemed_at > now() - interval '10 seconds' then
    return json_build_object('success', false, 'error', 'Already redeemed — please wait 10 seconds');
  end if;

  -- Rotate token + reset stamps
  v_new_token := gen_random_uuid()::text;
  update customers
    set stamps           = 0,
        qr_token         = v_new_token,
        qr_expires_at    = now() + interval '5 minutes',
        last_redeemed_at = now()
    where id = p_customer_id;

  insert into scan_events (merchant_id, customer_id, cashier_id, action, stamps_delta)
    values (p_merchant_id, p_customer_id, v_session.cashier_id, 'redeem_reward', 0);

  return json_build_object(
    'success',       true,
    'customer_name', v_customer.name,
    'message',       'Reward given. Stamps reset to 0.'
  );
end;
$$;

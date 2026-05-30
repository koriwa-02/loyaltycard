-- Verification codes table
create table if not exists verification_codes (
  id           uuid primary key default gen_random_uuid(),
  customer_id  uuid references customers(id) on delete cascade,
  code         text not null,
  expires_at   timestamptz not null default now() + interval '10 minutes',
  used         boolean default false,
  created_at   timestamptz default now()
);

-- RLS
alter table verification_codes enable row level security;
create policy "anon can insert verification codes"
  on verification_codes for insert with check (true);
create policy "anon can read own verification codes"
  on verification_codes for select using (true);

-- RPC: generate code, store it, return masked info
create or replace function request_verification_code(
  p_phone      text default null,
  p_email      text default null,
  p_merchant_id uuid default null
)
returns json
language plpgsql security definer
as $$
declare
  v_customer customers%rowtype;
  v_code     text;
begin
  -- Find the customer
  select * into v_customer
    from customers
    where merchant_id = p_merchant_id
      and (
        (p_phone is not null and phone = p_phone) or
        (p_email is not null and email = p_email)
      )
    limit 1;

  if v_customer.id is null then
    return json_build_object('success', false, 'error', 'No account found');
  end if;

  -- Rate limit: max 1 code per 60 seconds
  if exists (
    select 1 from verification_codes
    where customer_id = v_customer.id
      and created_at > now() - interval '60 seconds'
      and used = false
  ) then
    return json_build_object('success', false, 'error', 'Please wait 60 seconds before requesting a new code');
  end if;

  -- Invalidate old codes
  update verification_codes
    set used = true
    where customer_id = v_customer.id and used = false;

  -- Generate 6-digit code
  v_code := lpad(floor(random() * 1000000)::text, 6, '0');

  -- Store it
  insert into verification_codes (customer_id, code, expires_at)
    values (v_customer.id, v_code, now() + interval '10 minutes');

  -- Return masked contact + code (code shown in dev — replace with email in prod)
  return json_build_object(
    'success',      true,
    'customer_id',  v_customer.id,
    'masked_email', case when v_customer.email is not null
                    then left(v_customer.email, 2) || '****' || substring(v_customer.email from position('@' in v_customer.email))
                    else null end,
    'masked_phone', case when v_customer.phone is not null
                    then left(v_customer.phone, 4) || '****' || right(v_customer.phone, 2)
                    else null end,
    'code',         v_code  -- REMOVE THIS in production once email is wired
  );
end;
$$;

-- RPC: verify code → return card URL params
create or replace function verify_otp(
  p_customer_id uuid,
  p_code        text
)
returns json
language plpgsql security definer
as $$
declare
  v_vc   verification_codes%rowtype;
  v_cust customers%rowtype;
begin
  select * into v_vc
    from verification_codes
    where customer_id = p_customer_id
      and code = p_code
      and used = false
      and expires_at > now()
    order by created_at desc
    limit 1;

  if v_vc.id is null then
    return json_build_object('success', false, 'error', 'Invalid or expired code');
  end if;

  -- Mark used
  update verification_codes set used = true where id = v_vc.id;

  -- Get card params
  select * into v_cust from customers where id = p_customer_id;

  return json_build_object(
    'success',       true,
    'access_secret', v_cust.access_secret,
    'card_serial',   v_cust.card_serial
  );
end;
$$;

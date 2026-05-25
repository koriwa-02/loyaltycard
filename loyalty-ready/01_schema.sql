-- ============================================================
-- LOYALTY PLATFORM — SUPABASE SCHEMA (FIXED)
-- Tables created in correct dependency order
-- ============================================================

create extension if not exists "pgcrypto";

-- 1. MERCHANTS
create table merchants (
  id                uuid primary key default gen_random_uuid(),
  created_at        timestamptz not null default now(),
  name              text not null,
  slug              text not null unique,
  logo_url          text,
  brand_color       text not null default '#1D9E75',
  stamp_emoji       text not null default '☕',
  total_stamps      int  not null default 10,
  reward_label      text not null default '1 free coffee',
  points_per_visit  int  not null default 1,
  owner_email       text not null,
  owner_id          uuid references auth.users(id),
  plan              text not null default 'starter'
    check (plan in ('starter','growth','chain')),
  active            boolean not null default true
);

alter table merchants enable row level security;

create policy "merchant owner access"
  on merchants for all
  using (owner_id = auth.uid());

-- 2. CUSTOMERS
create table customers (
  id               uuid primary key default gen_random_uuid(),
  created_at       timestamptz not null default now(),
  merchant_id      uuid not null references merchants(id) on delete cascade,
  name             text not null,
  phone            text,
  email            text,
  birthday         date,
  referral_code    text unique default substring(gen_random_uuid()::text, 1, 8),
  referred_by      uuid references customers(id),
  stamps           int  not null default 0,
  lifetime_stamps  int  not null default 0,
  card_serial      text unique default gen_random_uuid()::text,
  apple_push_token text,
  google_pass_id   text,
  active           boolean not null default true,
  unique(merchant_id, phone),
  unique(merchant_id, email)
);

alter table customers enable row level security;

create policy "merchant sees own customers"
  on customers for all
  using (
    merchant_id in (
      select id from merchants where owner_id = auth.uid()
    )
  );

create policy "customer sees own row"
  on customers for select
  using (id = auth.uid());

create policy "public enrollment"
  on customers for insert
  with check (true);

-- 3. CASHIERS  ← must be before scan_events
create table cashiers (
  id           uuid primary key default gen_random_uuid(),
  created_at   timestamptz not null default now(),
  merchant_id  uuid not null references merchants(id) on delete cascade,
  user_id      uuid references auth.users(id),
  name         text not null,
  pin          text,
  active       boolean not null default true
);

alter table cashiers enable row level security;

create policy "merchant manages cashiers"
  on cashiers for all
  using (
    merchant_id in (
      select id from merchants where owner_id = auth.uid()
    )
  );

create policy "cashier sees own row"
  on cashiers for select
  using (user_id = auth.uid());

-- 4. SCAN EVENTS  ← after cashiers
create table scan_events (
  id            uuid primary key default gen_random_uuid(),
  created_at    timestamptz not null default now(),
  merchant_id   uuid not null references merchants(id),
  customer_id   uuid not null references customers(id),
  cashier_id    uuid references cashiers(id),
  action        text not null check (action in ('add_stamp', 'redeem_reward', 'void')),
  stamps_delta  int  not null default 1,
  note          text
);

alter table scan_events enable row level security;

create policy "merchant sees own scans"
  on scan_events for all
  using (
    merchant_id in (
      select id from merchants where owner_id = auth.uid()
    )
  );

create policy "cashier can insert scan"
  on scan_events for insert
  with check (
    merchant_id in (
      select merchant_id from cashiers where user_id = auth.uid() and active = true
    )
  );

-- 5. REWARDS
create table rewards (
  id            uuid primary key default gen_random_uuid(),
  merchant_id   uuid not null references merchants(id) on delete cascade,
  label         text not null,
  stamps_needed int  not null,
  active        boolean not null default true
);

alter table rewards enable row level security;

create policy "merchant manages rewards"
  on rewards for all
  using (
    merchant_id in (
      select id from merchants where owner_id = auth.uid()
    )
  );

-- 6. FUNCTIONS

create or replace function add_stamp(
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
  v_redeemed boolean := false;
begin
  select * into v_customer from customers where id = p_customer_id for update;
  select * into v_merchant from merchants where id = p_merchant_id;

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

create or replace function redeem_reward(
  p_customer_id uuid,
  p_cashier_id  uuid,
  p_merchant_id uuid
)
returns json
language plpgsql security definer
as $$
begin
  update customers set stamps = 0 where id = p_customer_id;

  insert into scan_events (merchant_id, customer_id, cashier_id, action, stamps_delta)
    values (p_merchant_id, p_customer_id, p_cashier_id, 'redeem_reward', 0);

  return json_build_object('success', true, 'message', 'Reward redeemed. Stamps reset to 0.');
end;
$$;

-- 7. INDEXES
create index on customers (merchant_id);
create index on customers (card_serial);
create index on customers (referral_code);
create index on scan_events (customer_id);
create index on scan_events (merchant_id);
create index on scan_events (created_at desc);

-- 8. DEMO MERCHANT
insert into merchants (name, slug, brand_color, stamp_emoji, total_stamps, reward_label, owner_email)
values ('Café Atlas Demo', 'cafe-atlas-demo', '#1D9E75', '☕', 8, '1 free coffee', 'demo@yourdomain.com');

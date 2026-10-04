-- The poaw node's database schema (PostgreSQL 14+). Self-hosters: `poaw-node init-db` applies this once to an empty
-- database, in one transaction. It's the node's tables only. A hosted service may add its own tables (accounts,
-- billing, ...) and extra columns alongside these; the node never depends on them.
-- Receipts, log leaves, log nodes and log roots are append-only: triggers refuse UPDATE, DELETE and TRUNCATE.

create schema if not exists qed;

create table qed.workspaces (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  created_at timestamptz not null default now()
);

-- Only a SHA-256 of the key is stored. The plaintext is shown once, at creation.
create table qed.api_keys (
  id           uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references qed.workspaces(id),
  key_hash     text not null unique,
  label        text,
  created_at   timestamptz not null default now(),
  revoked_at   timestamptz
);

create table qed.agents (
  id           uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references qed.workspaces(id),
  external_ref text not null,
  created_at   timestamptz not null default now(),
  unique (workspace_id, external_ref)
);

-- A connection names WHERE a credential lives (secret_ref). It never holds the credential.
create table qed.connections (
  id           uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references qed.workspaces(id),
  provider     text not null,                -- e.g. 'github'
  scopes       text[] not null default '{}',
  secret_ref   text not null,                -- e.g. Secrets Manager name
  status       text not null default 'active' check (status in ('active','revoked')),
  created_at   timestamptz not null default now(),
  revoked_at   timestamptz,
  unique (workspace_id, provider)
);

create table qed.claims (
  id              uuid primary key default gen_random_uuid(),
  workspace_id    uuid not null references qed.workspaces(id),
  agent_id        uuid not null references qed.agents(id),
  client_claim_id text not null,
  action          text not null,
  target          text not null,
  params          jsonb not null default '{}',
  claimed_at      timestamptz not null,
  claim_digest    text not null,
  deadline_at     timestamptz not null,
  state           text not null default 'queued' check (state in ('queued','decided')),
  attempts        integer not null default 0,
  next_attempt_at timestamptz not null default now(),
  last_error      text,
  created_at      timestamptz not null default now(),
  unique (workspace_id, client_claim_id)
);
create index claims_due on qed.claims (next_attempt_at) where state = 'queued';
create index claims_list on qed.claims (workspace_id, created_at desc, id desc);
create index claims_console on qed.claims (workspace_id, claimed_at desc);  -- the hosted console's history (#150)

-- Append-only Merkle log (SPEC §8). leaf_index is gapless: assigned under an advisory lock.
create table qed.log_leaves (
  leaf_index bigint primary key check (leaf_index >= 0),
  leaf_hash  bytea not null check (length(leaf_hash) = 32),
  receipt_id text not null unique,
  created_at timestamptz not null default now()
);

create table qed.receipts (
  id           text primary key,             -- body.receipt_id
  claim_id     uuid not null unique references qed.claims(id),
  workspace_id uuid not null references qed.workspaces(id),
  body         jsonb not null,
  signature    jsonb not null,
  leaf_index   bigint not null unique references qed.log_leaves(leaf_index),
  verdict      text not null,
  supersedes   text references qed.receipts(id),
  attestation_document text,                 -- level 3: base64url COSE_Sign1, beside the body (SPEC §4); body holds its SHA-256
  created_at   timestamptz not null default now()
);

create table qed.log_roots (
  tree_size   bigint primary key check (tree_size > 0),
  root_hash   bytea not null check (length(root_hash) = 32),
  computed_at timestamptz not null default now()
);

create table qed.alerts (
  id         uuid primary key default gen_random_uuid(),
  receipt_id text not null references qed.receipts(id),
  sink       text not null,
  status     text not null default 'pending' check (status in ('pending','sent','failed')),
  attempts   integer not null default 0,
  last_error text,
  created_at timestamptz not null default now(),
  sent_at    timestamptz
);

-- Receipts, log leaves and log roots are immutable (VISION: append-only; ARCHITECTURE invariant 2).
create or replace function qed.forbid_mutation() returns trigger language plpgsql as $$
begin
  raise exception 'qed.%: % is not allowed; records are append-only', tg_table_name, tg_op;
end $$;

create trigger receipts_append_only  before update or delete on qed.receipts   for each row execute function qed.forbid_mutation();
create trigger leaves_append_only    before update or delete on qed.log_leaves for each row execute function qed.forbid_mutation();
create trigger roots_append_only     before update or delete on qed.log_roots  for each row execute function qed.forbid_mutation();
create trigger receipts_no_truncate  before truncate on qed.receipts   for each statement execute function qed.forbid_mutation();
create trigger leaves_no_truncate    before truncate on qed.log_leaves for each statement execute function qed.forbid_mutation();
create trigger roots_no_truncate     before truncate on qed.log_roots  for each statement execute function qed.forbid_mutation();


-- Rate limiting (token buckets), used by the claims API and receipt reads.
create table qed.rate_buckets (
  k          text primary key,           -- 'key:<api_key_hash>' or 'ip:<client ip>'
  tokens     double precision not null,
  updated_at timestamptz not null default now()
);
alter table qed.rate_buckets enable row level security;

-- Refill at `rate_per_s`, cap at `burst`, take 1. Returns the tokens remaining after the take (< 0 = over the limit).
create or replace function qed.rate_take(p_k text, p_burst double precision, p_rate_per_s double precision)
returns double precision language sql as $$
  insert into qed.rate_buckets as b (k, tokens, updated_at) values (p_k, p_burst - 1, now())
  on conflict (k) do update
    set tokens = greatest(-1, least(p_burst, b.tokens + extract(epoch from (now() - b.updated_at)) * p_rate_per_s) - 1),
        updated_at = now()
  returning tokens
$$;


-- GitHub App installations as connections: a connection holds either an installation id or a secret reference.
alter table qed.connections add column installation_id bigint;
alter table qed.connections alter column secret_ref drop not null;
alter table qed.connections add constraint connections_github_needs_installation
  check (provider <> 'github' or installation_id is not null);
alter table qed.connections add constraint connections_credential_present
  check (installation_id is not null or secret_ref is not null);

-- API keys carry a short display prefix (the plaintext key itself is never stored; key_hash is its SHA-256).
alter table qed.api_keys add column key_prefix text;

create table qed.log_nodes (
  level  smallint not null check (level >= 0 and level < 64),
  idx    bigint   not null check (idx >= 0),
  hash   bytea    not null check (length(hash) = 32),
  primary key (level, idx)
);
create trigger nodes_append_only before update or delete on qed.log_nodes for each row execute function qed.forbid_mutation();
create trigger nodes_no_truncate before truncate on qed.log_nodes for each statement execute function qed.forbid_mutation();
alter table qed.log_nodes enable row level security;

-- One row per anchoring attempt, keyed by the tree size being anchored. The status moves pending → landed | failed.
-- (Not append-only: an anchor's status changes as the transaction confirms. The chain is the immutable record.)
create table qed.anchors (
  tree_size      bigint primary key references qed.log_roots(tree_size),
  root_hash      bytea not null check (length(root_hash) = 32),
  prev_tree_size bigint,
  chain          text not null,                  -- CAIP-2, e.g. eip155:84532
  tx_hash        text,
  eas_uid        text,
  block_number   bigint,
  block_time     timestamptz,
  gas_used       bigint,
  effective_gas_price_wei numeric,
  status         text not null default 'pending' check (status in ('pending','landed','failed')),
  attempts       integer not null default 0,
  last_error     text,
  created_at     timestamptz not null default now(),
  anchored_at    timestamptz
);
create index anchors_landed on qed.anchors (tree_size desc) where status = 'landed';
create unique index anchors_one_pending on qed.anchors ((status)) where status = 'pending';  -- one anchor in flight (#147)
alter table qed.anchors enable row level security;

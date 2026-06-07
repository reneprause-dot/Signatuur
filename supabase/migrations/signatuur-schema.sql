-- ================================================================
-- SIGNATUUR — Produktiv-Schema für Supabase
-- Fortgeschrittene Elektronische Signatur (FES) nach eIDAS Art. 26
-- ================================================================

-- ── EXTENSIONS ──────────────────────────────────────────────────
create extension if not exists "uuid-ossp";
create extension if not exists "pgcrypto";

-- ── ENUM TYPES ──────────────────────────────────────────────────
create type doc_status as enum (
  'draft',          -- erstellt, noch nicht versendet
  'pending_otp',    -- OTP an Unterzeichner gesendet
  'pending_sign',   -- OTP bestätigt, wartet auf Unterschrift
  'signed',         -- erfolgreich signiert
  'rejected',       -- vom Unterzeichner abgelehnt
  'revoked',        -- widerrufen
  'expired'         -- Signaturfrist abgelaufen
);

create type doc_type as enum (
  'nda', 'offer', 'contract', 'consent', 'invoice', 'other'
);

create type audit_event as enum (
  'created', 'otp_sent', 'otp_verified', 'viewed',
  'signed', 'rejected', 'revoked', 'expired', 'exported'
);

create type sig_level as enum ('ees', 'fes', 'qes');

-- ── PROFILES (erweitert Supabase Auth) ──────────────────────────
create table public.profiles (
  id            uuid primary key references auth.users(id) on delete cascade,
  full_name     text not null,
  organization  text,
  email         text not null,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

-- ── DOCUMENTS ───────────────────────────────────────────────────
create table public.documents (
  id                uuid primary key default uuid_generate_v4(),
  owner_id          uuid not null references public.profiles(id) on delete cascade,

  -- Metadaten
  title             text not null,
  doc_type          doc_type not null default 'other',
  description       text,
  status            doc_status not null default 'draft',
  sig_level         sig_level not null default 'fes',

  -- Unterzeichner
  signer_name       text not null,
  signer_email      text not null,

  -- Dokument-Datei
  file_path         text,           -- Supabase Storage path (original PDF)
  signed_file_path  text,           -- Supabase Storage path (signiertes PDF)
  file_hash_sha256  text,           -- SHA-256 des Original-PDFs

  -- Signatur
  signature_data    text,           -- base64 PNG der Unterschrift
  signature_typed   text,           -- falls getippt

  -- Kryptographische Integrität
  payload_hash      text,           -- SHA-256(titel+signatur+timestamp+signer)
  tsa_token         text,           -- RFC-3161 Zeitstempel-Token (base64)
  tsa_ts            timestamptz,    -- Zeitstempel aus TSA-Response
  tsa_serial        text,           -- Seriennummer des TSA-Tokens

  -- Audit
  signed_at         timestamptz,
  expires_at        timestamptz default (now() + interval '7 days'),
  revoked_at        timestamptz,
  revoke_reason     text,

  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);

-- ── OTP TOKENS ──────────────────────────────────────────────────
create table public.otp_tokens (
  id            uuid primary key default uuid_generate_v4(),
  document_id   uuid not null references public.documents(id) on delete cascade,
  email         text not null,
  token_hash    text not null,     -- bcrypt-Hash des 6-stelligen OTP
  attempts      int not null default 0,
  max_attempts  int not null default 5,
  expires_at    timestamptz not null default (now() + interval '15 minutes'),
  used_at       timestamptz,
  created_at    timestamptz not null default now()
);

-- ── AUDIT TRAIL ─────────────────────────────────────────────────
create table public.audit_trail (
  id            uuid primary key default uuid_generate_v4(),
  document_id   uuid not null references public.documents(id) on delete cascade,
  event         audit_event not null,

  -- Wer hat die Aktion ausgelöst?
  actor_user_id uuid references public.profiles(id),
  actor_email   text,              -- für externe Unterzeichner

  -- Technische Nachweise (serverseitig erfasst!)
  ip_address    inet,
  user_agent    text,
  device_type   text,
  country_code  text,

  -- Payload-Snapshot für Manipulationsnachweis
  payload_hash  text,
  notes         text,

  created_at    timestamptz not null default now()
);

-- ── REVOCATION LOG ──────────────────────────────────────────────
create table public.revocation_log (
  id            uuid primary key default uuid_generate_v4(),
  document_id   uuid not null references public.documents(id),
  revoked_by    uuid not null references public.profiles(id),
  reason        text not null,
  ip_address    inet,
  created_at    timestamptz not null default now()
);

-- ── DATENSCHUTZ: Einwilligungen ─────────────────────────────────
create table public.consent_log (
  id            uuid primary key default uuid_generate_v4(),
  document_id   uuid not null references public.documents(id),
  signer_email  text not null,
  consent_text  text not null,     -- exakter Wortlaut der Einwilligung
  ip_address    inet,
  accepted_at   timestamptz not null default now()
);

-- ================================================================
-- ROW LEVEL SECURITY
-- ================================================================

alter table public.profiles      enable row level security;
alter table public.documents     enable row level security;
alter table public.otp_tokens    enable row level security;
alter table public.audit_trail   enable row level security;
alter table public.revocation_log enable row level security;
alter table public.consent_log   enable row level security;

-- PROFILES
create policy "Eigenes Profil lesen"   on public.profiles for select using (auth.uid() = id);
create policy "Eigenes Profil ändern"  on public.profiles for update using (auth.uid() = id);
create policy "Profil anlegen"         on public.profiles for insert with check (auth.uid() = id);

-- DOCUMENTS: Besitzer hat vollen Zugriff
create policy "Dokumente lesen (Besitzer)"   on public.documents for select using (auth.uid() = owner_id);
create policy "Dokument anlegen"             on public.documents for insert with check (auth.uid() = owner_id);
create policy "Dokument ändern (Besitzer)"   on public.documents for update using (auth.uid() = owner_id);
create policy "Dokument löschen (Besitzer)"  on public.documents for delete using (auth.uid() = owner_id);

-- DOCUMENTS: Unterzeichner kann per Token lesen (Edge Function)
-- (Zugriff über service_role in Edge Functions, kein direkter RLS-Zugriff für Externe)

-- AUDIT TRAIL: Nur lesbar für Dokumenteigentümer
create policy "Audit lesen (Besitzer)" on public.audit_trail for select
  using (
    exists (
      select 1 from public.documents d
      where d.id = audit_trail.document_id
      and d.owner_id = auth.uid()
    )
  );

-- OTP TOKENS: Nur über Edge Functions (service_role)
-- Kein direkter Client-Zugriff

-- REVOCATION: Nur Besitzer
create policy "Widerruf lesen" on public.revocation_log for select
  using (
    exists (
      select 1 from public.documents d
      where d.id = revocation_log.document_id
      and d.owner_id = auth.uid()
    )
  );

-- CONSENT: Nur Besitzer
create policy "Einwilligung lesen" on public.consent_log for select
  using (
    exists (
      select 1 from public.documents d
      where d.id = consent_log.document_id
      and d.owner_id = auth.uid()
    )
  );

-- ================================================================
-- STORAGE BUCKETS
-- ================================================================
-- In Supabase Dashboard anlegen oder via API:
-- bucket: "documents-original"  (private, max 10MB)
-- bucket: "documents-signed"    (private, max 15MB)

-- ================================================================
-- AUTOMATISCHE UPDATED_AT
-- ================================================================
create or replace function public.handle_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger trg_documents_updated_at
  before update on public.documents
  for each row execute function public.handle_updated_at();

create trigger trg_profiles_updated_at
  before update on public.profiles
  for each row execute function public.handle_updated_at();

-- ================================================================
-- AUTOMATISCHES PROFIL BEI REGISTRIERUNG
-- ================================================================
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer as $$
begin
  insert into public.profiles (id, full_name, email)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
    new.email
  );
  return new;
end;
$$;

create trigger trg_on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ================================================================
-- AUTOMATISCHES ABLAUFEN VON DOKUMENTEN
-- ================================================================
-- Cron-Job via pg_cron (in Supabase unter Database > Extensions aktivieren):
-- select cron.schedule('expire-documents', '0 * * * *', $$
--   update public.documents
--   set status = 'expired'
--   where status in ('pending_otp', 'pending_sign')
--   and expires_at < now();
-- $$);

-- ================================================================
-- HILFSFUNKTION: Dokument-Status-Übersicht
-- ================================================================
create or replace function public.get_document_stats(user_id uuid)
returns table (
  total bigint,
  signed bigint,
  pending bigint,
  rejected bigint,
  revoked bigint
) language sql security definer as $$
  select
    count(*) as total,
    count(*) filter (where status = 'signed') as signed,
    count(*) filter (where status in ('pending_otp', 'pending_sign')) as pending,
    count(*) filter (where status = 'rejected') as rejected,
    count(*) filter (where status = 'revoked') as revoked
  from public.documents
  where owner_id = user_id;
$$;

-- ================================================================
-- LÖSCHFRISTEN-VIEW (DSGVO Art. 17)
-- ================================================================
create view public.deletion_candidates as
  select
    d.id,
    d.title,
    d.signer_email,
    d.signed_at,
    d.signed_at + interval '10 years' as deletion_due,
    d.owner_id
  from public.documents d
  where d.status = 'signed'
  and d.signed_at + interval '10 years' < now();

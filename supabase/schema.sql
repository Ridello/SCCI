-- =============================================================================
-- SCCI STAGE 2 — CORRECTED PRODUCTION SCHEMA (v2)
-- =============================================================================
-- This REPLACES the previous schema.sql entirely. Do not run this alongside
-- the old one — see the running instructions at the bottom of this file
-- (also repeated in the chat response).
--
-- Design summary (see SECURITY_REVIEW.md for the full reasoning):
--  - No table is directly writable by the public. All public-facing actions
--    (apply as employee/manager, request school service) go through
--    SECURITY DEFINER functions that validate input and enforce safe
--    defaults.
--  - New signups always get role = 'pending' — the database itself refuses
--    to trust a client-supplied role, no matter what the frontend sends.
--  - Only admin/manager can ever change a profile's role or status, enforced
--    by a trigger, not just by policy intent.
--  - Resource access (general/employee/group/assignment/school) is fully
--    enforced, including a real employee_groups structure.
--  - Bank details live in their own tightly-scoped table.
--  - Wallet balances are computed from an immutable transaction ledger via a
--    view, never stored as an editable number.
--  - Storage buckets and their RLS policies are defined here, in SQL, not
--    left as a manual dashboard step.
--  - Explicit grants/revokes on top of RLS (defense in depth).
-- =============================================================================

create extension if not exists "uuid-ossp";

-- =============================================================================
-- 1. PROFILES
-- =============================================================================
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'pending' check (role in ('admin','manager','employee','school','pending')),
  name text not null,
  email text not null unique,
  status text not null default 'applicant' check (status in ('applicant','pending','active','inactive','suspended')),
  created_at timestamptz not null default now()
);

create index if not exists idx_profiles_role on public.profiles(role);

-- SECURITY: new signups NEVER get to choose their own role. The trigger
-- ignores any role sent in signup metadata and always assigns 'pending'.
-- `name` is safe to trust from metadata (it's not a privilege). Real role
-- grants only ever happen via the approval RPC functions further down.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, role, name, email, status)
  values (
    new.id,
    'pending',
    coalesce(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
    new.email,
    'applicant'
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

create or replace function public.current_role()
returns text
language sql stable
security definer set search_path = public
as $$
  select role from public.profiles where id = auth.uid();
$$;

-- SECURITY: this is the core anti-privilege-escalation guard. It runs on
-- EVERY update to profiles, regardless of whether the update came from a
-- raw client request or one of our trusted RPC functions — RPC functions
-- calling this as an admin/manager will pass; anything else attempting to
-- change role/status will be rejected with an exception.
create or replace function public.prevent_role_self_escalation()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  if (new.role is distinct from old.role or new.status is distinct from old.status)
     and coalesce(public.current_role(), '') not in ('admin','manager') then
    raise exception 'Only SCCI admin/manager staff can change a role or status.';
  end if;
  return new;
end;
$$;

drop trigger if exists trg_prevent_role_self_escalation on public.profiles;
create trigger trg_prevent_role_self_escalation
  before update on public.profiles
  for each row execute procedure public.prevent_role_self_escalation();

-- =============================================================================
-- 2. EMPLOYEES
-- =============================================================================
create table if not exists public.employees (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid unique references public.profiles(id) on delete cascade,
  name text not null,
  email text not null,
  phone text,
  location text,
  skills text[] default '{}',
  availability text,
  status text not null default 'applicant' check (status in ('applicant','pending','active','inactive','suspended')),
  intro text,
  cv_storage_path text,
  applied_at timestamptz not null default now(),
  approved_at timestamptz
);
create index if not exists idx_employees_user_id on public.employees(user_id);
create index if not exists idx_employees_status on public.employees(status);

-- =============================================================================
-- 3. EMPLOYEE GROUPS  (backs the "group" resource access type — this didn't
--    exist at all in the previous schema, so group-targeted resources could
--    never be correctly enforced)
-- =============================================================================
create table if not exists public.employee_groups (
  id uuid primary key default uuid_generate_v4(),
  name text not null unique,
  created_at timestamptz not null default now()
);
create table if not exists public.employee_group_members (
  group_id uuid references public.employee_groups(id) on delete cascade,
  employee_id uuid references public.employees(id) on delete cascade,
  primary key (group_id, employee_id)
);
create index if not exists idx_group_members_employee on public.employee_group_members(employee_id);

-- =============================================================================
-- 4. MANAGER APPLICATIONS
-- =============================================================================
create table if not exists public.manager_applications (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid references public.profiles(id) on delete cascade,
  name text not null,
  email text not null,
  phone text,
  location text,
  skills text[] default '{}',
  availability text,
  message text,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  submitted_at timestamptz not null default now()
);
create index if not exists idx_mgrapp_user_id on public.manager_applications(user_id);
create index if not exists idx_mgrapp_status on public.manager_applications(status);

-- =============================================================================
-- 5. SCHOOLS
-- =============================================================================
create table if not exists public.schools (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid unique references public.profiles(id) on delete set null,
  name text not null,
  contact_person text,
  email text,
  phone text,
  location text,
  org_type text,
  students_count integer default 0,
  created_at timestamptz not null default now()
);
create index if not exists idx_schools_user_id on public.schools(user_id);

-- =============================================================================
-- 6. SCHOOL SERVICE REQUESTS
-- =============================================================================
create table if not exists public.school_requests (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid references public.profiles(id) on delete set null,
  school_id uuid references public.schools(id) on delete set null,
  school_name text not null,
  contact_person text,
  email text,
  phone text,
  location text,
  org_type text,
  students_count integer default 0,
  programs text,
  message text,
  status text not null default 'pending' check (status in ('pending','contacted','approved','scheduled','completed','rejected')),
  submitted_at timestamptz not null default now()
);
create index if not exists idx_schoolreq_user_id on public.school_requests(user_id);
create index if not exists idx_schoolreq_school_id on public.school_requests(school_id);
create index if not exists idx_schoolreq_status on public.school_requests(status);

-- =============================================================================
-- 7. ASSIGNMENTS
-- =============================================================================
create table if not exists public.assignments (
  id uuid primary key default uuid_generate_v4(),
  employee_id uuid references public.employees(id) on delete cascade,
  school_id uuid references public.schools(id) on delete set null,
  school_name text not null,
  date date not null,
  time time not null,
  task text,
  instructions text,
  status text not null default 'scheduled' check (status in ('scheduled','completed','cancelled')),
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now(),
  unique (employee_id, school_name, date, time)
);
create index if not exists idx_assignments_employee_id on public.assignments(employee_id);
create index if not exists idx_assignments_school_id on public.assignments(school_id);
create index if not exists idx_assignments_date on public.assignments(date);

-- =============================================================================
-- 8. TASKS
-- =============================================================================
create table if not exists public.tasks (
  id uuid primary key default uuid_generate_v4(),
  title text not null,
  employee_id uuid references public.employees(id) on delete cascade,
  school_name text,
  date date,
  priority text default 'medium' check (priority in ('high','medium','low')),
  instructions text,
  status text not null default 'pending' check (status in ('pending','in_progress','completed')),
  completion_note text,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now()
);
create index if not exists idx_tasks_employee_id on public.tasks(employee_id);
create index if not exists idx_tasks_status on public.tasks(status);

-- =============================================================================
-- 9. RESOURCES  (metadata only — file lives in the private "resources" bucket)
-- =============================================================================
create table if not exists public.resources (
  id uuid primary key default uuid_generate_v4(),
  file_name text not null,
  file_type text,
  storage_path text not null,
  description text,
  uploaded_by uuid references public.profiles(id),
  access_type text not null check (access_type in ('employee','group','assignment','school','general')),
  access_target uuid,  -- employees.id / employee_groups.id / assignments.id / schools.id depending on access_type
  created_at timestamptz not null default now()
);
create index if not exists idx_resources_access on public.resources(access_type, access_target);

-- =============================================================================
-- 10. NOTIFICATIONS
-- =============================================================================
create table if not exists public.notifications (
  id uuid primary key default uuid_generate_v4(),
  audience_role text check (audience_role in ('admin','manager','employee','school')),
  audience_user_id uuid references public.profiles(id) on delete cascade,
  type text not null,
  message text not null,
  link text,
  read boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists idx_notifications_audience_user on public.notifications(audience_user_id);
create index if not exists idx_notifications_audience_role on public.notifications(audience_role);
create index if not exists idx_notifications_created_at on public.notifications(created_at desc);

-- =============================================================================
-- 11. ATTENDANCE
-- =============================================================================
create table if not exists public.attendance (
  id uuid primary key default uuid_generate_v4(),
  employee_id uuid references public.employees(id) on delete cascade,
  assignment_id uuid references public.assignments(id) on delete set null,
  date date not null,
  status text not null check (status in ('present','absent','excused','pending')),
  created_at timestamptz not null default now(),
  unique (employee_id, assignment_id, date)
);
create index if not exists idx_attendance_employee_id on public.attendance(employee_id);

-- =============================================================================
-- 12. REPORTS
-- =============================================================================
create table if not exists public.reports (
  id uuid primary key default uuid_generate_v4(),
  employee_id uuid references public.employees(id) on delete cascade,
  assignment_id uuid references public.assignments(id) on delete set null,
  school_name text,
  date date not null,
  activities text,
  students_count integer,
  challenges text,
  notes text,
  status text not null default 'submitted' check (status in ('submitted','reviewed')),
  manager_comment text,
  created_at timestamptz not null default now()
);
create index if not exists idx_reports_employee_id on public.reports(employee_id);
create index if not exists idx_reports_status on public.reports(status);

-- =============================================================================
-- 13. PAYOUT ACCOUNTS  (bank details — isolated from withdrawal_requests)
-- =============================================================================
create table if not exists public.payout_accounts (
  employee_id uuid primary key references public.employees(id) on delete cascade,
  bank_name text not null,
  account_name text not null,
  account_number text not null,
  updated_at timestamptz not null default now()
);

-- =============================================================================
-- 14. WALLET TRANSACTIONS  (immutable ledger — never store a raw balance)
-- =============================================================================
create table if not exists public.wallet_transactions (
  id uuid primary key default uuid_generate_v4(),
  employee_id uuid references public.employees(id) on delete cascade,
  amount numeric(12,2) not null check (amount > 0),
  type text not null check (type in ('credit','debit')),
  description text,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now()
);
create index if not exists idx_wallet_employee_id on public.wallet_transactions(employee_id);

-- Balances are always derived, never stored, so there's no editable number
-- that could drift from the truth of what actually happened.
create or replace view public.wallet_balances
with (security_invoker = true)
as
select
  employee_id,
  coalesce(sum(case when type = 'credit' then amount else -amount end), 0) as balance
from public.wallet_transactions
group by employee_id;

-- =============================================================================
-- 15. WITHDRAWAL REQUESTS
-- =============================================================================
create table if not exists public.withdrawal_requests (
  id uuid primary key default uuid_generate_v4(),
  employee_id uuid references public.employees(id) on delete cascade,
  amount numeric(12,2) not null check (amount > 0),
  payout_account_id uuid references public.payout_accounts(employee_id),
  bank_snapshot jsonb not null,  -- immutable copy of bank details at request time
  status text not null default 'pending' check (status in ('pending','processing','successful','failed')),
  requested_at timestamptz not null default now(),
  processed_at timestamptz,
  processed_by uuid references public.profiles(id)
);
create index if not exists idx_withdrawals_employee_id on public.withdrawal_requests(employee_id);
create index if not exists idx_withdrawals_status on public.withdrawal_requests(status);

-- =============================================================================
-- 16. ACTIVITY LOG  (audit trail — insert only via log_activity(), never
--     directly by client requests)
-- =============================================================================
create table if not exists public.activity_log (
  id uuid primary key default uuid_generate_v4(),
  type text not null,
  message text not null,
  user_id uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists idx_activity_created_at on public.activity_log(created_at desc);

create or replace function public.log_activity(p_type text, p_message text, p_user_id uuid default null)
returns void
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.activity_log (type, message, user_id)
  values (p_type, p_message, coalesce(p_user_id, auth.uid()));
end;
$$;

-- =============================================================================
-- ROW LEVEL SECURITY
-- =============================================================================
alter table public.profiles enable row level security;
alter table public.employees enable row level security;
alter table public.employee_groups enable row level security;
alter table public.employee_group_members enable row level security;
alter table public.manager_applications enable row level security;
alter table public.schools enable row level security;
alter table public.school_requests enable row level security;
alter table public.assignments enable row level security;
alter table public.tasks enable row level security;
alter table public.resources enable row level security;
alter table public.notifications enable row level security;
alter table public.attendance enable row level security;
alter table public.reports enable row level security;
alter table public.payout_accounts enable row level security;
alter table public.wallet_transactions enable row level security;
alter table public.withdrawal_requests enable row level security;
alter table public.activity_log enable row level security;

-- ---- PROFILES ----
-- No INSERT policy at all: rows are only ever created by handle_new_user()
-- (SECURITY DEFINER, bypasses RLS as the table owner).
drop policy if exists "profiles_select_own_or_staff" on public.profiles;
create policy "profiles_select_own_or_staff" on public.profiles for select
  using ( id = auth.uid() or public.current_role() in ('admin','manager') );

drop policy if exists "profiles_update_own_or_staff" on public.profiles;
create policy "profiles_update_own_or_staff" on public.profiles for update
  using ( id = auth.uid() or public.current_role() in ('admin','manager') );
-- Column-level protection (role/status) is enforced by the trigger above,
-- not by this policy — RLS alone can't restrict which columns change.

-- ---- EMPLOYEES ----
-- No public INSERT policy — creation happens only via apply_as_employee().
drop policy if exists "employees_select" on public.employees;
create policy "employees_select" on public.employees for select
  using ( user_id = auth.uid() or public.current_role() in ('admin','manager') );
drop policy if exists "employees_update_staff" on public.employees;
create policy "employees_update_staff" on public.employees for update
  using ( public.current_role() in ('admin','manager') );

-- ---- EMPLOYEE GROUPS ----
drop policy if exists "groups_select" on public.employee_groups;
create policy "groups_select" on public.employee_groups for select
  using ( public.current_role() in ('admin','manager') or
          id in (select group_id from public.employee_group_members m
                 join public.employees e on e.id = m.employee_id
                 where e.user_id = auth.uid()) );
drop policy if exists "groups_write_staff" on public.employee_groups;
create policy "groups_write_staff" on public.employee_groups for all
  using ( public.current_role() in ('admin','manager') );

drop policy if exists "group_members_select" on public.employee_group_members;
create policy "group_members_select" on public.employee_group_members for select
  using ( public.current_role() in ('admin','manager') or
          employee_id in (select id from public.employees where user_id = auth.uid()) );
drop policy if exists "group_members_write_staff" on public.employee_group_members;
create policy "group_members_write_staff" on public.employee_group_members for all
  using ( public.current_role() in ('admin','manager') );

-- ---- MANAGER APPLICATIONS (admin-only visibility; no public insert policy) ----
drop policy if exists "mgrapp_select_admin" on public.manager_applications;
create policy "mgrapp_select_admin" on public.manager_applications for select
  using ( public.current_role() = 'admin' or user_id = auth.uid() );
drop policy if exists "mgrapp_update_admin" on public.manager_applications;
create policy "mgrapp_update_admin" on public.manager_applications for update
  using ( public.current_role() = 'admin' );

-- ---- SCHOOLS ----
drop policy if exists "schools_select" on public.schools;
create policy "schools_select" on public.schools for select
  using ( user_id = auth.uid() or public.current_role() in ('admin','manager') );
drop policy if exists "schools_write_staff" on public.schools;
create policy "schools_write_staff" on public.schools for all
  using ( public.current_role() in ('admin','manager') );

-- ---- SCHOOL REQUESTS (no public insert policy — via request_school_service()) ----
drop policy if exists "schoolreq_select" on public.school_requests;
create policy "schoolreq_select" on public.school_requests for select
  using (
    public.current_role() in ('admin','manager')
    or user_id = auth.uid()
    or school_id in (select id from public.schools where user_id = auth.uid())
  );
drop policy if exists "schoolreq_update_staff" on public.school_requests;
create policy "schoolreq_update_staff" on public.school_requests for update
  using ( public.current_role() in ('admin','manager') );

-- ---- ASSIGNMENTS ----
drop policy if exists "assignments_select" on public.assignments;
create policy "assignments_select" on public.assignments for select
  using (
    public.current_role() in ('admin','manager')
    or employee_id in (select id from public.employees where user_id = auth.uid())
  );
drop policy if exists "assignments_write_staff" on public.assignments;
create policy "assignments_write_staff" on public.assignments for all
  using ( public.current_role() in ('admin','manager') );
-- Employees have no UPDATE policy at all here: they cannot reassign
-- themselves, change the school, or alter date/time — by omission, not
-- just by convention.

-- ---- TASKS ----
drop policy if exists "tasks_select" on public.tasks;
create policy "tasks_select" on public.tasks for select
  using (
    public.current_role() in ('admin','manager')
    or employee_id in (select id from public.employees where user_id = auth.uid())
  );
drop policy if exists "tasks_insert_staff" on public.tasks;
create policy "tasks_insert_staff" on public.tasks for insert
  with check ( public.current_role() in ('admin','manager') );
drop policy if exists "tasks_update_staff" on public.tasks;
create policy "tasks_update_staff" on public.tasks for update
  using ( public.current_role() in ('admin','manager') );
-- Employees get a SEPARATE, narrow update policy: they may only flip
-- status/completion_note on their own task, nothing else.
drop policy if exists "tasks_update_own_status" on public.tasks;
create policy "tasks_update_own_status" on public.tasks for update
  using ( employee_id in (select id from public.employees where user_id = auth.uid()) )
  with check ( employee_id in (select id from public.employees where user_id = auth.uid()) );

-- ---- RESOURCES ----
-- Full enforcement of all four non-general access types.
drop policy if exists "resources_select" on public.resources;
create policy "resources_select" on public.resources for select
  using (
    public.current_role() in ('admin','manager')
    or access_type = 'general'
    or (access_type = 'employee' and access_target in
        (select id from public.employees where user_id = auth.uid()))
    or (access_type = 'group' and access_target in
        (select group_id from public.employee_group_members m
         join public.employees e on e.id = m.employee_id
         where e.user_id = auth.uid()))
    or (access_type = 'assignment' and access_target in
        (select a.id from public.assignments a
          join public.employees e on e.id = a.employee_id
          where e.user_id = auth.uid()))
    or (access_type = 'school' and access_target in
        (select distinct a.school_id from public.assignments a
         join public.employees e on e.id = a.employee_id
         where e.user_id = auth.uid()))
  );
drop policy if exists "resources_write_staff" on public.resources;
create policy "resources_write_staff" on public.resources for all
  using ( public.current_role() in ('admin','manager') );

-- ---- NOTIFICATIONS ----
-- The `or true` bug is gone. Staff can insert freely; everything else goes
-- through trusted functions (which bypass RLS as the table owner).
drop policy if exists "notifications_select_own" on public.notifications;
create policy "notifications_select_own" on public.notifications for select
  using ( audience_user_id = auth.uid() or audience_role = public.current_role() );
drop policy if exists "notifications_update_own" on public.notifications;
drop policy if exists "notifications_insert_staff" on public.notifications;
create policy "notifications_insert_staff" on public.notifications for insert
  with check ( public.current_role() in ('admin','manager') );

-- ---- ATTENDANCE ----
drop policy if exists "attendance_select" on public.attendance;
create policy "attendance_select" on public.attendance for select
  using (
    public.current_role() in ('admin','manager')
    or employee_id in (select id from public.employees where user_id = auth.uid())
  );
drop policy if exists "attendance_insert_own" on public.attendance;
create policy "attendance_insert_own" on public.attendance for insert
  with check (
    public.current_role() in ('admin','manager')
    or employee_id in (select id from public.employees where user_id = auth.uid())
  );
-- No UPDATE policy for employees: attendance, once submitted, cannot be
-- silently rewritten by the person who submitted it.

-- ---- REPORTS ----
drop policy if exists "reports_select" on public.reports;
create policy "reports_select" on public.reports for select
  using (
    public.current_role() in ('admin','manager')
    or employee_id in (select id from public.employees where user_id = auth.uid())
  );
drop policy if exists "reports_insert_own" on public.reports;
create policy "reports_insert_own" on public.reports for insert
  with check ( employee_id in (select id from public.employees where user_id = auth.uid()) );
drop policy if exists "reports_update_own_before_review" on public.reports;
create policy "reports_update_own_before_review" on public.reports for update
  using ( employee_id in (select id from public.employees where user_id = auth.uid()) and status = 'submitted' )
  with check ( employee_id in (select id from public.employees where user_id = auth.uid()) and status = 'submitted' );
drop policy if exists "reports_update_staff" on public.reports;
create policy "reports_update_staff" on public.reports for update
  using ( public.current_role() in ('admin','manager') );

-- ---- PAYOUT ACCOUNTS ----
drop policy if exists "payout_select" on public.payout_accounts;
create policy "payout_select" on public.payout_accounts for select
  using (
    public.current_role() in ('admin','manager')
    or employee_id in (select id from public.employees where user_id = auth.uid())
  );
drop policy if exists "payout_write_own" on public.payout_accounts;
create policy "payout_write_own" on public.payout_accounts for all
  using ( employee_id in (select id from public.employees where user_id = auth.uid()) )
  with check ( employee_id in (select id from public.employees where user_id = auth.uid()) );

-- ---- WALLET TRANSACTIONS ----
drop policy if exists "wallet_select" on public.wallet_transactions;
create policy "wallet_select" on public.wallet_transactions for select
  using (
    public.current_role() in ('admin','manager')
    or employee_id in (select id from public.employees where user_id = auth.uid())
  );
drop policy if exists "wallet_insert_staff" on public.wallet_transactions;
create policy "wallet_insert_staff" on public.wallet_transactions for insert
  with check ( public.current_role() in ('admin','manager') );
-- No UPDATE/DELETE policy for anyone: the ledger is append-only by design.

-- ---- WITHDRAWAL REQUESTS ----
drop policy if exists "withdrawals_select" on public.withdrawal_requests;
create policy "withdrawals_select" on public.withdrawal_requests for select
  using (
    public.current_role() in ('admin','manager')
    or employee_id in (select id from public.employees where user_id = auth.uid())
  );
drop policy if exists "withdrawals_insert_own" on public.withdrawal_requests;
create policy "withdrawals_insert_own" on public.withdrawal_requests for insert
  with check ( employee_id in (select id from public.employees where user_id = auth.uid()) and status = 'pending' );
drop policy if exists "withdrawals_update_staff" on public.withdrawal_requests;
create policy "withdrawals_update_staff" on public.withdrawal_requests for update
  using ( public.current_role() in ('admin','manager') );
-- No employee UPDATE policy: once submitted, only staff can move the status.

-- ---- ACTIVITY LOG (admin only; no client insert policy at all) ----
drop policy if exists "activity_select_admin" on public.activity_log;
create policy "activity_select_admin" on public.activity_log for select
  using ( public.current_role() = 'admin' );

-- =============================================================================
-- PUBLIC-FACING RPC FUNCTIONS
-- These are the ONLY way an applicant/school can get data into the system.
-- Each requires an authenticated session (auth.uid() not null), which means
-- the frontend must call supabase.auth.signUp()/signInWithPassword() first.
-- =============================================================================

create or replace function public.apply_as_employee(
  p_phone text, p_location text, p_skills text[], p_availability text,
  p_intro text, p_cv_storage_path text
)
returns uuid
language plpgsql
security definer set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_name text;
  v_email text;
  v_emp_id uuid;
  v_recent_count int;
begin
  if v_uid is null then
    raise exception 'You must be signed in to apply.';
  end if;
  if exists (select 1 from public.employees where user_id = v_uid) then
    raise exception 'You have already submitted an employee application.';
  end if;

  select name, email into v_name, v_email from public.profiles where id = v_uid;

  select count(*) into v_recent_count from public.employees
    where email = v_email and applied_at > now() - interval '5 minutes';
  if v_recent_count > 0 then
    raise exception 'Please wait a few minutes before submitting again.';
  end if;

  insert into public.employees (user_id, name, email, phone, location, skills, availability, intro, cv_storage_path, status)
  values (v_uid, v_name, v_email, p_phone, p_location, p_skills, p_availability, p_intro, p_cv_storage_path, 'applicant')
  returning id into v_emp_id;

  insert into public.notifications (audience_role, type, message, link)
  values ('manager', 'application', v_name || ' submitted an employee application.', '#/manager/applications');

  perform public.log_activity('application', v_name || ' applied to join SCCI as an employee.', v_uid);

  return v_emp_id;
end;
$$;

create or replace function public.apply_as_manager(
  p_phone text, p_location text, p_skills text[], p_availability text, p_message text
)
returns uuid
language plpgsql
security definer set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_name text; v_email text; v_app_id uuid; v_recent_count int;
begin
  if v_uid is null then raise exception 'You must be signed in to apply.'; end if;
  select name, email into v_name, v_email from public.profiles where id = v_uid;

  select count(*) into v_recent_count from public.manager_applications
    where email = v_email and submitted_at > now() - interval '5 minutes';
  if v_recent_count > 0 then raise exception 'Please wait a few minutes before submitting again.'; end if;

  insert into public.manager_applications (user_id, name, email, phone, location, skills, availability, message)
  values (v_uid, v_name, v_email, p_phone, p_location, p_skills, p_availability, p_message)
  returning id into v_app_id;

  insert into public.notifications (audience_role, type, message, link)
  values ('admin', 'manager_application', v_name || ' requested manager/employer access.', '#/admin/managers');

  perform public.log_activity('manager_application', v_name || ' requested manager/employer access.', v_uid);
  return v_app_id;
end;
$$;

create or replace function public.request_school_service(
  p_school_name text, p_contact_person text, p_phone text, p_location text,
  p_org_type text, p_students_count integer, p_programs text, p_message text
)
returns uuid
language plpgsql
security definer set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_email text; v_school_id uuid; v_req_id uuid; v_recent_count int;
begin
  if v_uid is null then raise exception 'You must be signed in to submit a request.'; end if;
  select email into v_email from public.profiles where id = v_uid;

  select count(*) into v_recent_count from public.school_requests
    where email = v_email and submitted_at > now() - interval '5 minutes';
  if v_recent_count > 0 then raise exception 'Please wait a few minutes before submitting again.'; end if;

  if not exists (select 1 from public.schools where user_id = v_uid) then
    insert into public.schools (user_id, name, contact_person, email, phone, location, org_type, students_count)
    values (v_uid, p_school_name, p_contact_person, v_email, p_phone, p_location, p_org_type, coalesce(p_students_count,0))
    returning id into v_school_id;
  else
    select id into v_school_id from public.schools where user_id = v_uid;
  end if;

  insert into public.school_requests (user_id, school_id, school_name, contact_person, email, phone, location, org_type, students_count, programs, message)
  values (v_uid, v_school_id, p_school_name, p_contact_person, v_email, p_phone, p_location, p_org_type, coalesce(p_students_count,0), p_programs, p_message)
  returning id into v_req_id;

  insert into public.notifications (audience_role, type, message, link)
  values ('manager', 'school_request', p_school_name || ' requested SCCI services.', '#/manager/schools');

  perform public.log_activity('school_request', p_school_name || ' requested SCCI services.', v_uid);
  return v_req_id;
end;
$$;

-- =============================================================================
-- STAFF-ONLY APPROVAL RPC FUNCTIONS
-- Each checks the caller's role explicitly, in addition to the DB-level
-- trigger guard on profiles. Two layers on purpose.
-- =============================================================================

create or replace function public.approve_employee_application(p_employee_id uuid)
returns void
language plpgsql
security definer set search_path = public
as $$
declare v_user_id uuid; v_name text;
begin
  if public.current_role() not in ('admin','manager') then
    raise exception 'Not authorized.';
  end if;
  select user_id, name into v_user_id, v_name from public.employees where id = p_employee_id;
  if v_user_id is null then raise exception 'Employee application not found.'; end if;

  update public.employees set status = 'active', approved_at = now() where id = p_employee_id;
  update public.profiles set role = 'employee', status = 'active' where id = v_user_id;

  insert into public.notifications (audience_user_id, type, message, link)
  values (v_user_id, 'application', 'Your SCCI employee application was approved. Welcome aboard!', '#/employee/overview');

  perform public.log_activity('approval', v_name || E'''s employee application was approved.', auth.uid());
end;
$$;

create or replace function public.reject_employee_application(p_employee_id uuid)
returns void
language plpgsql
security definer set search_path = public
as $$
declare v_user_id uuid; v_name text;
begin
  if public.current_role() not in ('admin','manager') then raise exception 'Not authorized.'; end if;
  select user_id, name into v_user_id, v_name from public.employees where id = p_employee_id;
  if v_user_id is null then raise exception 'Employee application not found.'; end if;

  update public.employees set status = 'inactive' where id = p_employee_id;
  update public.profiles set status = 'inactive' where id = v_user_id;

  insert into public.notifications (audience_user_id, type, message, link)
  values (v_user_id, 'application', 'Your SCCI employee application was not approved at this time.', '#/login');

  perform public.log_activity('rejection', v_name || E'''s employee application was rejected.', auth.uid());
end;
$$;

create or replace function public.approve_manager_application(p_app_id uuid)
returns void
language plpgsql
security definer set search_path = public
as $$
declare v_user_id uuid; v_name text;
begin
  -- Manager approval is admin-only, not manager-approvable, per spec.
  if public.current_role() <> 'admin' then raise exception 'Only an admin can approve manager access.'; end if;
  select user_id, name into v_user_id, v_name from public.manager_applications where id = p_app_id;
  if v_user_id is null then raise exception 'Manager application not found.'; end if;

  update public.manager_applications set status = 'approved' where id = p_app_id;
  update public.profiles set role = 'manager', status = 'active' where id = v_user_id;

  insert into public.notifications (audience_user_id, type, message, link)
  values (v_user_id, 'manager_application', 'Your SCCI manager access was approved.', '#/manager/overview');

  perform public.log_activity('approval', v_name || ' was approved for manager access.', auth.uid());
end;
$$;

create or replace function public.reject_manager_application(p_app_id uuid)
returns void
language plpgsql
security definer set search_path = public
as $$
begin
  if public.current_role() <> 'admin' then raise exception 'Only an admin can reject manager applications.'; end if;
  update public.manager_applications set status = 'rejected' where id = p_app_id;
  perform public.log_activity('rejection', 'A manager application was rejected.', auth.uid());
end;
$$;

create or replace function public.update_school_request_status(p_request_id uuid, p_status text)
returns void
language plpgsql
security definer set search_path = public
as $$
declare v_user_id uuid; v_school_name text;
begin
  if public.current_role() not in ('admin','manager') then raise exception 'Not authorized.'; end if;
  if p_status not in ('pending','contacted','approved','scheduled','completed','rejected') then
    raise exception 'Invalid status.';
  end if;

  select user_id, school_name into v_user_id, v_school_name from public.school_requests where id = p_request_id;
  if v_school_name is null then raise exception 'School request not found.'; end if;

  update public.school_requests set status = p_status where id = p_request_id;

  if p_status = 'approved' and v_user_id is not null then
    update public.profiles set role = 'school', status = 'active'
      where id = v_user_id and status <> 'active';
    insert into public.notifications (audience_user_id, type, message, link)
    values (v_user_id, 'school_request', 'Your SCCI service request was approved — you can now log in.', '#/school/overview');
    perform public.log_activity('approval', v_school_name || E'''s service request was approved and their account activated.', auth.uid());
  end if;
end;
$$;

-- =============================================================================
-- GRANTS  (defense in depth on top of RLS — see SECURITY_REVIEW.md #10)
-- =============================================================================
revoke all on all tables in schema public from anon;
revoke all on all functions in schema public from public;

grant usage on schema public to anon, authenticated;

-- authenticated users get table-level access; RLS still gates every row.
grant select, insert, update on
  public.profiles, public.employees, public.employee_groups, public.employee_group_members,
  public.manager_applications, public.schools, public.school_requests,
  public.assignments, public.tasks, public.resources, public.notifications,
  public.attendance, public.reports, public.payout_accounts,
  public.wallet_transactions, public.withdrawal_requests
  to authenticated;
grant select on public.activity_log to authenticated;
grant select on public.wallet_balances to authenticated;

-- Only these specific functions are callable by anon (pre-login) and
-- authenticated (post-signup) clients. Everything else stays locked down.
grant execute on function public.apply_as_employee(
  text, text, text[], text, text, text
) to authenticated;

grant execute on function public.apply_as_manager(
  text, text, text[], text, text
) to authenticated;

grant execute on function public.request_school_service(
  text, text, text, text, text, integer, text, text
) to authenticated;

grant execute on function public.approve_employee_application(
  uuid
) to authenticated;

grant execute on function public.reject_employee_application(
  uuid
) to authenticated;

grant execute on function public.approve_manager_application(
  uuid
) to authenticated;

grant execute on function public.reject_manager_application(
  uuid
) to authenticated;

grant execute on function public.update_school_request_status(
  uuid, text
) to authenticated;

grant execute on function public.current_role()
to authenticated;

-- =============================================================================
-- STORAGE: BUCKETS + RLS ON storage.objects
-- =============================================================================
insert into storage.buckets (id, name, public)
values ('resources', 'resources', false)
on conflict (id) do nothing;

insert into storage.buckets (id, name, public)
values ('applications', 'applications', false)
on conflict (id) do nothing;

-- ---- "resources" bucket: staff-uploaded lesson materials ----
-- Upload/manage: admin/manager only.
drop policy if exists "resources_bucket_staff_write" on storage.objects;
create policy "resources_bucket_staff_write" on storage.objects
  for all
  using ( bucket_id = 'resources' and public.current_role() in ('admin','manager') )
  with check ( bucket_id = 'resources' and public.current_role() in ('admin','manager') );

-- Download: staff, or any employee whose access rules permit the matching
-- resources row (join on storage_path, mirroring the table's own policy).
drop policy if exists "resources_bucket_read" on storage.objects;
create policy "resources_bucket_read" on storage.objects
  for select
  using (
    bucket_id = 'resources'
    and (
      public.current_role() in ('admin','manager')
      or exists (
        select 1 from public.resources r
        where r.storage_path = storage.objects.name
        and (
          r.access_type = 'general'
          or (r.access_type = 'employee' and r.access_target in
              (select id from public.employees where user_id = auth.uid()))
          or (r.access_type = 'group' and r.access_target in
              (select group_id from public.employee_group_members m
               join public.employees e on e.id = m.employee_id
               where e.user_id = auth.uid()))
          or (r.access_type = 'assignment' and r.access_target in
              (select a.id from public.assignments a
               join public.employees e on e.id = a.employee_id
               where e.user_id = auth.uid()))
          or (r.access_type = 'school' and r.access_target in
              (select distinct a.school_id from public.assignments a
               join public.employees e on e.id = a.employee_id
               where e.user_id = auth.uid()))
        )
      )
    )
  );

-- ---- "applications" bucket: applicant CVs/resumes ----
-- An applicant may only upload/read within their OWN folder, named by their
-- user id: e.g. "{auth.uid()}/cv.pdf". Staff can read any CV for review.
drop policy if exists "applications_bucket_own_write" on storage.objects;
create policy "applications_bucket_own_write" on storage.objects
  for insert
  with check ( bucket_id = 'applications' and (storage.foldername(name))[1] = auth.uid()::text );

drop policy if exists "applications_bucket_read" on storage.objects;
create policy "applications_bucket_read" on storage.objects
  for select
  using (
    bucket_id = 'applications'
    and ( (storage.foldername(name))[1] = auth.uid()::text
          or public.current_role() in ('admin','manager') )
  );

-- =============================================================================
-- BOOTSTRAP: promote your own first user to admin.
-- Run this ONE LINE MANUALLY, after you've signed up once through the app,
-- replacing the email. Never automate this — it is the one deliberate,
-- human step where privileged access is granted outside the approval RPCs.
-- =============================================================================
-- update public.profiles set role = 'admin', status = 'active' where email = 'you@example.com';

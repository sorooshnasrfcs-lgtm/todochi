-- ============================================================
--  طرح دیتابیس داشبورد برنامه‌ریزی (چندکاربره)
--  این فایل را یک‌بار در Supabase → SQL Editor اجرا کن.
-- ============================================================

-- ۱) پروفایل کاربران (نقش و وضعیت تأیید توسط ادمین)
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  email      text,
  full_name  text not null default '',
  role       text not null default 'user' check (role in ('user','admin')),
  approved   boolean not null default false,
  created_at timestamptz not null default now()
);

-- ۲) کارهای هر کاربر (هر ردیف متعلق به یک کاربر است)
create table if not exists public.tasks (
  user_id    uuid   not null default auth.uid() references auth.users(id) on delete cascade,
  id         text   not null,
  position   bigint not null default 0,
  data       jsonb  not null,
  updated_at timestamptz not null default now(),
  primary key (user_id, id)
);
create index if not exists tasks_user_pos on public.tasks (user_id, position desc);

-- ۳) توابع کمکی (security definer تا در سیاست‌ها حلقه ایجاد نشود)
create or replace function public.is_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles
                 where id = auth.uid() and role = 'admin' and approved)
$$;

create or replace function public.is_approved() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles
                 where id = auth.uid() and approved)
$$;

-- فقط تعداد کارهای هر کاربر را به ادمین می‌دهد (نه محتوای کارها)
create or replace function public.admin_task_counts()
returns table (user_id uuid, n bigint)
language sql security definer stable set search_path = public as $$
  select t.user_id, count(*) from public.tasks t
  where public.is_admin() group by t.user_id
$$;

-- ۴) ساخت خودکار پروفایل هنگام ثبت‌نام (در ابتدا تأیید‌نشده)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, full_name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data ->> 'full_name', ''));
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ۵) امنیت سطح ردیف (RLS)
alter table public.profiles enable row level security;
alter table public.tasks    enable row level security;

drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles
  for select using (id = auth.uid() or public.is_admin());

drop policy if exists profiles_admin_update on public.profiles;
create policy profiles_admin_update on public.profiles
  for update using (public.is_admin()) with check (public.is_admin());

drop policy if exists tasks_own on public.tasks;
create policy tasks_own on public.tasks
  for all
  using      (user_id = auth.uid() and public.is_approved())
  with check (user_id = auth.uid() and public.is_approved());

-- ۶) آخرین قدم (بعد از ثبت‌نام خودت در سایت): خودت را ادمین کن.
--    ایمیل را عوض کن و این خط را جداگانه اجرا کن:
--
--    update public.profiles set role = 'admin', approved = true
--    where email = 'your-email@example.com';

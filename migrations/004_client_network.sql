-- Insyrium Portal · migration 004 — client network tracking (real IP + MAC).
-- Run once against an existing database. Fresh installs pick these columns
-- up automatically from the SQLAlchemy models via `flask --app app init-db`.

ALTER TABLE sessions
  ADD COLUMN mac_address VARCHAR(17) NULL AFTER ip_address;

ALTER TABLE users
  ADD COLUMN last_login_ip VARCHAR(45) NULL AFTER last_login_at,
  ADD COLUMN last_login_mac VARCHAR(17) NULL AFTER last_login_ip;

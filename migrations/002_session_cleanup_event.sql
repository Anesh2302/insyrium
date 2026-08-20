-- Insyrium Portal · migration 002 — purge expired sessions hourly.
-- (Replaces Mongo's TTL index — MySQL has no equivalent.)
SET GLOBAL event_scheduler = ON;

CREATE EVENT IF NOT EXISTS purge_expired_sessions
ON SCHEDULE EVERY 1 HOUR
DO
  DELETE FROM sessions WHERE expires_at < NOW();

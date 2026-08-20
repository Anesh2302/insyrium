-- Insyrium Portal · migration 003 — purge expired OTP codes every 5 minutes
-- (they expire in minutes, not days).
CREATE EVENT IF NOT EXISTS purge_expired_otp_codes
ON SCHEDULE EVERY 5 MINUTE
DO
  DELETE FROM otp_codes WHERE expires_at < NOW();

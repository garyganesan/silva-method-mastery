-- Silva Method Mastery CMS - D1 Database Schema

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT    PRIMARY KEY,
  email      TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS otp_codes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT    NOT NULL,
  code       TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS content (
  page        TEXT NOT NULL,
  content_key TEXT NOT NULL,
  value       TEXT NOT NULL,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (page, content_key)
);

CREATE TABLE IF NOT EXISTS gmail_oauth (
  id            INTEGER PRIMARY KEY,
  refresh_token TEXT    NOT NULL,
  access_token  TEXT,
  token_expiry  INTEGER
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

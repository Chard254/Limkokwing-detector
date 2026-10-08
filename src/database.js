import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { config } from './config.js';

fs.mkdirSync(path.dirname(config.sqlitePath), { recursive: true });
export const db = new DatabaseSync(config.sqlitePath);
db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS url_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    result TEXT,
    verdict TEXT,
    risk_level TEXT,
    score INTEGER,
    risk_score INTEGER,
    reasons TEXT,
    reason TEXT,
    advice TEXT,
    source TEXT NOT NULL DEFAULT 'web',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_url_scans_url_created ON url_scans(url, created_at DESC);
  CREATE TABLE IF NOT EXISTS conversation_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone_number TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'IDLE',
    context TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone_number TEXT NOT NULL,
    role TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_conversations_phone_created ON conversations(phone_number, created_at);
  CREATE TABLE IF NOT EXISTS whatsapp_message_statuses (
    message_id TEXT PRIMARY KEY,
    recipient_id TEXT,
    status TEXT NOT NULL,
    timestamp TEXT,
    error_code INTEGER,
    error_title TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS whatsapp_inbound_messages (
    message_id TEXT PRIMARY KEY,
    sender_id TEXT,
    status TEXT NOT NULL DEFAULT 'processing',
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

export function closeDatabase() {
  db.close();
}

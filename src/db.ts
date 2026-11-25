/**
 * What security.agent keeps: sign-in states, sessions and counters.
 *
 * A session row holds the person's ThreatCrush tokens sealed with AES-256-GCM
 * under SECAGENT_KEY, and is found by the SHA-256 of the cookie, so neither a
 * copy of the database nor a copy of the cookie alone opens anything. There is
 * no user table: ThreatCrush knows who the person is, we only hold their grant.
 * Nothing that was looked up is stored. The counters are totals per day.
 */
import { Database } from 'bun:sqlite'
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import type { Tokens } from './threatcrush.js'

export class Sealer {
  private readonly key: Buffer
  constructor(secret: string) {
    if (!secret || secret.length < 16) throw new Error('SECAGENT_KEY must be set (32 random bytes, hex)')
    this.key = createHash('sha256').update(secret).digest()
  }
  seal(plain: string): string {
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', this.key, iv)
    const body = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
    return [iv, cipher.getAuthTag(), body].map((b) => b.toString('base64')).join('.')
  }
  open(sealed: string): string {
    const [iv, tag, body] = sealed.split('.').map((s) => Buffer.from(s, 'base64'))
    const decipher = createDecipheriv('aes-256-gcm', this.key, iv!)
    decipher.setAuthTag(tag!)
    return Buffer.concat([decipher.update(body!), decipher.final()]).toString('utf8')
  }
}

const hash = (value: string) => createHash('sha256').update(value).digest('hex')
const STATE_TTL = 10 * 60_000
export const SESSION_TTL = 30 * 86_400_000

export type Session = { tokens: Tokens; clientId: string; sub: string; createdAt: number }
export type SavedState = { verifier: string; redirectUri: string; clientId: string }

export class Store {
  readonly db: Database
  constructor(path: string, readonly sealer: Sealer) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true })
    this.db = new Database(path, { create: true })
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS states (state TEXT PRIMARY KEY, verifier TEXT NOT NULL, redirect_uri TEXT NOT NULL, client_id TEXT NOT NULL, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (id_hash TEXT PRIMARY KEY, sealed TEXT NOT NULL, client_id TEXT NOT NULL, sub TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, seen_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS stats (day TEXT NOT NULL, name TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, name));
    `)
  }

  // Sign-in states: single use, ten minutes.
  saveState(state: string, s: SavedState, now = Date.now()): void {
    this.db.query('DELETE FROM states WHERE created_at < ?').run(now - STATE_TTL)
    this.db.query('INSERT INTO states (state, verifier, redirect_uri, client_id, created_at) VALUES (?, ?, ?, ?, ?)').run(hash(state), this.sealer.seal(s.verifier), s.redirectUri, s.clientId, now)
  }
  takeState(state: string, now = Date.now()): SavedState | null {
    if (!state) return null
    const row = this.db.query('DELETE FROM states WHERE state = ? RETURNING verifier, redirect_uri, client_id, created_at').get(hash(state)) as { verifier: string; redirect_uri: string; client_id: string; created_at: number } | null
    if (!row || row.created_at < now - STATE_TTL) return null
    return { verifier: this.sealer.open(row.verifier), redirectUri: row.redirect_uri, clientId: row.client_id }
  }

  // Sessions.
  newSession(tokens: Tokens, clientId: string, sub = '', now = Date.now()): string {
    const sid = randomBytes(32).toString('base64url')
    this.db.query('DELETE FROM sessions WHERE seen_at < ?').run(now - SESSION_TTL)
    this.db.query('INSERT INTO sessions (id_hash, sealed, client_id, sub, created_at, seen_at) VALUES (?, ?, ?, ?, ?, ?)').run(hash(sid), this.sealer.seal(JSON.stringify(tokens)), clientId, sub, now, now)
    return sid
  }
  session(sid: string | undefined, now = Date.now()): Session | null {
    if (!sid) return null
    const row = this.db.query('SELECT sealed, client_id, sub, created_at, seen_at FROM sessions WHERE id_hash = ?').get(hash(sid)) as { sealed: string; client_id: string; sub: string; created_at: number; seen_at: number } | null
    if (!row || row.seen_at < now - SESSION_TTL) return null
    try {
      return { tokens: JSON.parse(this.sealer.open(row.sealed)) as Tokens, clientId: row.client_id, sub: row.sub, createdAt: row.created_at }
    } catch {
      return null
    }
  }
  /** Keep a refreshed token pair (the old refresh token is dead once ThreatCrush answers). */
  saveTokens(sid: string, tokens: Tokens, now = Date.now()): void {
    this.db.query('UPDATE sessions SET sealed = ?, seen_at = ? WHERE id_hash = ?').run(this.sealer.seal(JSON.stringify(tokens)), now, hash(sid))
  }
  endSession(sid: string | undefined): void {
    if (sid) this.db.query('DELETE FROM sessions WHERE id_hash = ?').run(hash(sid))
  }

  // Settings the app learns once (the OAuth client ThreatCrush issued us).
  get(key: string): string | null {
    return (this.db.query('SELECT value FROM kv WHERE key = ?').get(key) as { value: string } | null)?.value ?? null
  }
  set(key: string, value: string): void {
    this.db.query('INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value').run(key, value)
  }

  // Counters: how many, never who or what.
  count(name: string, now = Date.now()): void {
    this.db.query('INSERT INTO stats (day, name, n) VALUES (?, ?, 1) ON CONFLICT (day, name) DO UPDATE SET n = n + 1').run(new Date(now).toISOString().slice(0, 10), name)
  }
  stats(days = 30, now = Date.now()): { day: string; name: string; n: number }[] {
    const since = new Date(now - days * 86_400_000).toISOString().slice(0, 10)
    return this.db.query('SELECT day, name, n FROM stats WHERE day >= ? ORDER BY day DESC, name').all(since) as { day: string; name: string; n: number }[]
  }
}

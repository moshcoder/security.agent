/**
 * Desktops: a signed-in person's own computer, reachable by their AI agent
 * through security.agent, driven by the W3BS Agentic Desktop Layer
 * (https://w3bs.org/desktop).
 *
 * The connection runs both ways over ONE outbound SSH connection that the
 * desktop opens, so the desktop needs no open port, no public address and no
 * VPN:
 *
 *   desktop -> server   the desktop runs `ssh -N -R localhost:<port>:127.0.0.1:7801
 *                       secagent-tunnel@<host>` (a systemd user unit that restarts
 *                       forever). Its key is allowed to do exactly one thing on the
 *                       server: listen on its own loopback port. No shell, no other
 *                       forwards (`restrict,port-forwarding,permitlisten=…`).
 *   server -> desktop   security.agent calls 127.0.0.1:<port> on the server; SSH
 *                       carries it back down the same connection to the W3BS
 *                       desktop broker's MCP endpoint on the desktop's own loopback
 *                       (127.0.0.1:7801), with the agent token the person made for
 *                       us. The broker's own gates still apply: the person is asked
 *                       before an agent drives, sees what it does, and can stop it
 *                       (tray, Super+Alt+Escape) or cut the tunnel at any time.
 *
 * This is the same arrangement dev2 already has with bonita (dev2-tunnel.service
 * on bonita: `ssh -N -R 2222:localhost:22`), generalized to one port per desktop
 * and narrowed from SSH to the desktop broker's MCP.
 *
 * Keys reach sshd through AuthorizedKeysCommand: the app writes every desktop's
 * restricted line to one file (SECAGENT_TUNNEL_KEYS) and a root-owned script in
 * deploy/tunnel prints it. Removing a desktop removes its line at once.
 */
import type { Database } from 'bun:sqlite'
import { randomBytes } from 'node:crypto'
import { renameSync, writeFileSync } from 'node:fs'
import { request } from 'node:http'
import type { Sealer } from './db.js'

export const PORT_MIN = 20000
export const PORT_MAX = 29999
export const BROKER_PORT = 7801

export type Desktop = { id: string; owner: string; name: string; publicKey: string; port: number; brokerPort: number; createdAt: number; seenAt: number | null }

export class DesktopError extends Error {
  constructor(message: string, readonly status = 400) {
    super(message)
  }
}

const KEY_TYPES = /^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa)$/

/** An OpenSSH public key line, reduced to "type base64" (any options or comment are dropped). */
export function parsePublicKey(input: unknown): string {
  const parts = String(input ?? '').trim().split(/\s+/)
  const at = parts.findIndex((p) => KEY_TYPES.test(p))
  const type = parts[at]
  const body = parts[at + 1]
  if (at < 0 || !type || !body || !/^[A-Za-z0-9+/]{60,2000}={0,3}$/.test(body)) throw new DesktopError('Paste the public key: one line starting with ssh-ed25519 (from ~/.ssh/security-agent-tunnel.pub).')
  const blob = Buffer.from(body, 'base64')
  const len = blob.readUInt32BE(0)
  if (blob.subarray(4, 4 + len).toString() !== type) throw new DesktopError('That public key is damaged: its type does not match its contents.')
  if (type === 'ssh-rsa' && blob.length < 270) throw new DesktopError('That RSA key is too short. Use ssh-ed25519.')
  return `${type} ${body}`
}

const cleanName = (v: unknown) => String(v ?? '').replace(/[\u0000-\u001f\u007f<>"'`\\]/g, '').trim().slice(0, 60)

export class Desktops {
  constructor(private readonly db: Database, private readonly sealer: Sealer, private readonly keysFile: string | null = null) {
    db.exec(`CREATE TABLE IF NOT EXISTS desktops (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, public_key TEXT NOT NULL UNIQUE,
      port INTEGER NOT NULL UNIQUE, broker_port INTEGER NOT NULL DEFAULT ${BROKER_PORT}, token TEXT NOT NULL,
      created_at INTEGER NOT NULL, seen_at INTEGER)`)
    db.exec('CREATE INDEX IF NOT EXISTS desktops_owner ON desktops (owner)')
  }

  private row = (r: Record<string, unknown>): Desktop => ({ id: r.id as string, owner: r.owner as string, name: r.name as string, publicKey: r.public_key as string, port: r.port as number, brokerPort: r.broker_port as number, createdAt: r.created_at as number, seenAt: (r.seen_at as number | null) ?? null })

  list(owner: string): Desktop[] {
    return (this.db.query('SELECT * FROM desktops WHERE owner = ? ORDER BY created_at').all(owner) as Record<string, unknown>[]).map(this.row)
  }
  get(owner: string, id: string): Desktop | null {
    const r = this.db.query('SELECT * FROM desktops WHERE owner = ? AND id = ?').get(owner, id) as Record<string, unknown> | null
    return r ? this.row(r) : null
  }
  token(id: string): string | null {
    const r = this.db.query('SELECT token FROM desktops WHERE id = ?').get(id) as { token: string } | null
    return r ? this.sealer.open(r.token) : null
  }

  add(owner: string, input: { name?: unknown; publicKey?: unknown; token?: unknown; brokerPort?: unknown }, now = Date.now()): Desktop {
    if (!owner) throw new DesktopError('Sign in with ThreatCrush first.', 401)
    const name = cleanName(input.name) || 'My desktop'
    const publicKey = parsePublicKey(input.publicKey)
    const token = String(input.token ?? '').trim()
    if (!/^[\x21-\x7e]{16,512}$/.test(token)) throw new DesktopError('Paste the agent token from `w3bs desktop agents add security-agent` (it saves it to ~/.config/w3bs/desktop/tokens/security-agent.token).')
    const brokerPort = input.brokerPort === undefined || input.brokerPort === '' ? BROKER_PORT : Number(input.brokerPort)
    if (!Number.isInteger(brokerPort) || brokerPort < 1 || brokerPort > 65535) throw new DesktopError('The broker port is a number from 1 to 65535 (default 7801).')
    if (this.list(owner).length >= 5) throw new DesktopError('Five desktops is the limit for now. Remove one first.')
    if (this.db.query('SELECT 1 FROM desktops WHERE public_key = ?').get(publicKey)) throw new DesktopError('That key is already used by a desktop. Make a new key for each desktop.')
    const used = new Set((this.db.query('SELECT port FROM desktops').all() as { port: number }[]).map((r) => r.port))
    let port = 0
    for (let tries = 0; tries < 50 && !port; tries++) {
      const p = PORT_MIN + (randomBytes(2).readUInt16BE(0) % (PORT_MAX - PORT_MIN + 1))
      if (!used.has(p)) port = p
    }
    if (!port) throw new DesktopError('No tunnel port is free. Try again later.', 503)
    const id = `dt_${randomBytes(9).toString('base64url')}`
    this.db.query('INSERT INTO desktops (id, owner, name, public_key, port, broker_port, token, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, owner, name, publicKey, port, brokerPort, this.sealer.seal(token), now)
    this.writeKeys()
    return this.get(owner, id)!
  }

  remove(owner: string, id: string): boolean {
    const r = this.db.query('DELETE FROM desktops WHERE owner = ? AND id = ?').run(owner, id)
    this.writeKeys()
    return r.changes > 0
  }

  seen(id: string, now = Date.now()): void {
    this.db.query('UPDATE desktops SET seen_at = ? WHERE id = ?').run(now, id)
  }

  /** One restricted authorized_keys line per desktop: listen on its own loopback port, nothing else. */
  authorizedKeys(): string {
    const rows = this.db.query('SELECT id, public_key, port FROM desktops ORDER BY port').all() as { id: string; public_key: string; port: number }[]
    return rows.map((r) => `restrict,port-forwarding,permitlisten="localhost:${r.port}",permitopen="none",command="/bin/false" ${r.public_key} security-agent-${r.id}\n`).join('')
  }

  /** Rewrite the keys file sshd reads (atomic rename, so sshd never sees half a file). */
  writeKeys(): void {
    if (!this.keysFile) return
    const tmp = `${this.keysFile}.tmp-${process.pid}`
    writeFileSync(tmp, this.authorizedKeys(), { mode: 0o644 })
    renameSync(tmp, this.keysFile)
  }
}

// ─── Talking to the desktop broker through the tunnel ───

type RpcResult = { status: number; sessionId: string | null; body: Record<string, unknown> | null }

/**
 * One HTTP request to the broker at the far end of the tunnel. node:http, not
 * fetch, because the broker refuses a Host that is not its own loopback address
 * and port, and the tunnel's server end is a different port: we must say
 * Host: 127.0.0.1:7801 ourselves. No Origin header is ever sent (the broker
 * refuses those too, so no web page can reach it).
 */
function brokerHttp(d: { port: number; brokerPort: number }, token: string, method: 'POST' | 'DELETE', body: unknown, sessionId: string | null, timeoutMs = 20_000): Promise<RpcResult> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? '' : JSON.stringify(body)
    const req = request(
      {
        host: '127.0.0.1',
        port: d.port,
        method,
        path: '/mcp',
        setHost: false,
        headers: {
          host: `127.0.0.1:${d.brokerPort}`,
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          accept: 'application/json',
          'content-length': Buffer.byteLength(payload),
          ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = []
        let size = 0
        res.on('data', (c: Buffer) => {
          size += c.length
          if (size > 8 * 1024 * 1024) req.destroy(new Error('the desktop answered with more than 8 MB'))
          else chunks.push(c)
        })
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8')
          let parsed: Record<string, unknown> | null = null
          try {
            parsed = text ? (JSON.parse(text) as Record<string, unknown>) : null
          } catch {}
          resolve({ status: res.statusCode ?? 0, sessionId: (res.headers['mcp-session-id'] as string | undefined) ?? null, body: parsed })
        })
      },
    )
    req.on('timeout', () => req.destroy(new Error('the desktop did not answer in time')))
    req.on('error', (e: NodeJS.ErrnoException) => reject(new DesktopError(e.code === 'ECONNREFUSED' ? 'The desktop is not connected: its tunnel is down (start the security-agent-tunnel unit on it).' : `The desktop did not answer: ${e.message}`, 502)))
    req.end(payload)
  })
}

export type BrokerCall = (d: Desktop, token: string, tool: string, args: Record<string, unknown>) => Promise<unknown>

const sessions = new Map<string, { id: string; at: number }>()
let rpcId = 0

/** Open (or reuse) an MCP session with the desktop's broker. */
async function brokerSession(d: Desktop, token: string): Promise<string> {
  const known = sessions.get(d.id)
  if (known && known.at > Date.now() - 10 * 60_000) return known.id
  const r = await brokerHttp(d, token, 'POST', { jsonrpc: '2.0', id: ++rpcId, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'security.agent', version: '0.1.0' } } }, null)
  if (r.status === 401) throw new DesktopError('The desktop refused our agent token. Make a new one with `w3bs desktop agents add security-agent` and update the desktop here.', 401)
  if (r.status === 403 || r.status === 421) throw new DesktopError('The desktop broker refused the connection. Is it started with --mcp-http 127.0.0.1:7801?', 502)
  if (r.status === 404) throw new DesktopError('The desktop broker has MCP over HTTP off. Start it with `w3bs desktop daemon --mcp-http 127.0.0.1:7801`.', 502)
  if (!r.sessionId) throw new DesktopError(`The desktop broker did not open a session (HTTP ${r.status}).`, 502)
  await brokerHttp(d, token, 'POST', { jsonrpc: '2.0', method: 'notifications/initialized' }, r.sessionId).catch(() => {})
  sessions.set(d.id, { id: r.sessionId, at: Date.now() })
  return r.sessionId
}

/** Call one desktop tool. MCP content comes back as is (screenshots are image content). */
export const brokerCall: BrokerCall = async (d, token, tool, args) => {
  for (let attempt = 0; attempt < 2; attempt++) {
    const sid = await brokerSession(d, token)
    const r = await brokerHttp(d, token, 'POST', { jsonrpc: '2.0', id: ++rpcId, method: 'tools/call', params: { name: tool, arguments: args } }, sid, 60_000)
    if (r.status === 404 && attempt === 0) {
      sessions.delete(d.id)
      continue
    }
    const err = r.body?.error as { message?: string } | undefined
    if (err) throw new DesktopError(`The desktop said: ${err.message ?? 'error'}`, 502)
    if (r.status >= 400 || !r.body?.result) throw new DesktopError(`The desktop answered HTTP ${r.status}.`, 502)
    sessions.set(d.id, { id: sid, at: Date.now() })
    return r.body.result
  }
  throw new DesktopError('The desktop kept dropping the session.', 502)
}

/** The desktop tools an agent may call through security.agent (the broker decides what each agent may actually do). */
export const DESKTOP_TOOLS = [
  'desktop_status', 'desktop_capabilities', 'desktop_layout', 'desktop_windows', 'desktop_inspect', 'desktop_screenshot',
  'task_begin', 'task_end', 'mouse_move', 'mouse_click', 'mouse_drag', 'mouse_scroll', 'mouse_hover',
  'keyboard_type', 'keyboard_press', 'keyboard_shortcut', 'input_batch', 'approval_status',
  'desktop_locate', 'desktop_remember', 'desktop_memory', 'human_step', 'human_step_status',
] as const

/** What the person runs on the desktop, filled in for this desktop. */
export function setupScript(d: { port: number; brokerPort: number }, sshHost: string, sshUser = 'secagent-tunnel'): string {
  return `# 1. The W3BS desktop layer, with MCP over HTTP on the desktop's own loopback
curl -fsSL https://w3bs.org/desktop/install.sh | sh
w3bs desktop agents add security-agent --preset broad
cat ~/.config/w3bs/desktop/tokens/security-agent.token  # paste this into security.agent
# (the installer runs the broker as: w3bs-desktop daemon --adapter auto --mcp-http 127.0.0.1:${d.brokerPort})

# 2. A key that can only open this tunnel
ssh-keygen -t ed25519 -N '' -C security-agent-tunnel -f ~/.ssh/security-agent-tunnel
cat ~/.ssh/security-agent-tunnel.pub                    # paste this into security.agent too

# 3. The tunnel: one outbound connection, kept up forever
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/security-agent-tunnel.service <<'UNIT'
[Unit]
Description=security.agent tunnel (desktop broker <-> ${sshHost})
After=network-online.target

[Service]
ExecStart=/usr/bin/ssh -N -T -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=accept-new -i %h/.ssh/security-agent-tunnel -R localhost:${d.port}:127.0.0.1:${d.brokerPort} ${sshUser}@${sshHost}
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload
systemctl --user enable --now security-agent-tunnel
loginctl enable-linger "$USER"   # keep it up when you are logged out

# Cut it any time:  systemctl --user disable --now security-agent-tunnel`
}

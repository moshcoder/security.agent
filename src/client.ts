/**
 * The terminal's side: sign in with ThreatCrush from a shell, keep the token on
 * this machine, and ask ThreatCrush directly. Used by the CLI, the TUI and the
 * stdio MCP server. Nothing here goes through the security.agent website.
 *
 * Credential, in order: THREATCRUSH_API_KEY (a tc_agent_ key, for servers and
 * CI with no browser), else the OAuth grant from `securityagent login`, kept in
 * ~/.config/securityagent/credentials.json (0600) and refreshed as it lapses.
 */
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import * as tc from './threatcrush.js'
import { AuthRequired, type Check, type Fetch, type Tokens } from './threatcrush.js'

type Saved = { base: string; clientId: string; tokens: Tokens }

export const configDir = () => join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'securityagent')

export type ClientOptions = { base?: string; fetch?: Fetch; dir?: string; apiKey?: string | null }

export class SecurityAgentClient {
  readonly base: string
  private readonly file: string
  private readonly o: { base: string; fetch?: Fetch }
  private readonly apiKey: string | null
  constructor(options: ClientOptions = {}) {
    this.base = (options.base ?? process.env.THREATCRUSH_URL ?? tc.THREATCRUSH).replace(/\/+$/, '')
    this.file = join(options.dir ?? configDir(), 'credentials.json')
    this.o = { base: this.base, ...(options.fetch ? { fetch: options.fetch } : {}) }
    this.apiKey = options.apiKey === undefined ? process.env.THREATCRUSH_API_KEY || null : options.apiKey
  }

  private saved(): Saved | null {
    try {
      const s = JSON.parse(readFileSync(this.file, 'utf8')) as Saved
      return s.base === this.base && s.clientId && s.tokens?.refreshToken ? s : null
    } catch {
      return null
    }
  }
  private save(s: Saved): void {
    mkdirSync(join(this.file, '..'), { recursive: true, mode: 0o700 })
    writeFileSync(this.file, JSON.stringify(s, null, 2), { mode: 0o600 })
    chmodSync(this.file, 0o600)
  }

  /** How this machine is signed in, without calling anyone. */
  status(): { signedIn: boolean; via: 'api-key' | 'oauth' | null; expiresAt?: number } {
    if (this.apiKey) return { signedIn: true, via: 'api-key' }
    const s = this.saved()
    return s ? { signedIn: true, via: 'oauth', expiresAt: s.tokens.expiresAt } : { signedIn: false, via: null }
  }

  /** The Bearer to send, or null when this machine has not signed in. */
  async bearer(): Promise<string | null> {
    if (this.apiKey) return this.apiKey
    const s = this.saved()
    if (!s) return null
    if (s.tokens.expiresAt - 60_000 > Date.now()) return s.tokens.accessToken
    try {
      const tokens = await tc.refresh({ refreshToken: s.tokens.refreshToken, clientId: s.clientId }, this.o)
      this.save({ ...s, tokens })
      return tokens.accessToken
    } catch (e) {
      if (e instanceof AuthRequired) rmSync(this.file, { force: true })
      throw e
    }
  }

  /**
   * Sign in with ThreatCrush: OAuth 2.1, authorization code with PKCE, a public
   * client registered for a loopback redirect (RFC 8252). `open` is told the URL
   * to visit; the promise settles when the browser comes back.
   */
  async login(open: (url: string) => void, timeoutMs = 5 * 60_000): Promise<void> {
    const state = tc.pkce().verifier
    const { verifier, challenge } = tc.pkce()
    let finish!: (r: { code?: string; error?: string }) => void
    const answered = new Promise<{ code?: string; error?: string }>((resolve) => (finish = resolve))
    const page = (title: string, text: string) =>
      new Response(`<!doctype html><meta charset="utf-8"><title>${title}</title><body style="font:16px system-ui;background:#07090c;color:#e6edf3;text-align:center;padding:4rem 1rem"><h1>${title}</h1><p>${text}</p>`, { headers: { 'content-type': 'text/html; charset=utf-8' } })
    const server = Bun.serve({
      hostname: '127.0.0.1',
      port: 0,
      fetch(request) {
        const u = new URL(request.url)
        if (u.pathname !== '/callback') return new Response('not found', { status: 404 })
        if (u.searchParams.get('state') !== state) return page('Not signed in', 'That answer does not belong to this sign-in. Run securityagent login again.')
        const error = u.searchParams.get('error')
        if (error) {
          finish({ error: u.searchParams.get('error_description') ?? error })
          return page('Not signed in', 'ThreatCrush did not sign you in. You can close this tab.')
        }
        finish({ code: u.searchParams.get('code') ?? '' })
        return page('Signed in', 'security.agent is connected to ThreatCrush. You can close this tab and go back to your terminal.')
      },
    })
    try {
      const redirectUri = `http://127.0.0.1:${server.port}/callback`
      // ThreatCrush matches a loopback redirect on any port, so one registration serves every login.
      const clientId = this.saved()?.clientId ?? (await tc.registerClient({ name: 'security.agent CLI', redirectUris: ['http://127.0.0.1/callback'], clientUri: 'https://security.agent.pit.world' }, this.o))
      open(tc.authorizeUrl({ clientId, redirectUri, state, challenge }, this.o))
      const timer = setTimeout(() => finish({ error: 'Nobody finished signing in within five minutes.' }), timeoutMs)
      const r = await answered
      clearTimeout(timer)
      if (r.error || !r.code) throw new AuthRequired(r.error ?? 'ThreatCrush sent no code.')
      const tokens = await tc.exchangeCode({ code: r.code, verifier, clientId, redirectUri }, this.o)
      this.save({ base: this.base, clientId, tokens })
    } finally {
      // Let the browser read the page before the listener goes away.
      setTimeout(() => server.stop(true), 500).unref?.()
    }
  }

  /** Revoke the grant at ThreatCrush and forget it here. */
  async logout(): Promise<boolean> {
    const s = this.saved()
    if (s) await tc.revoke(s.tokens.refreshToken, this.o)
    const had = existsSync(this.file)
    rmSync(this.file, { force: true })
    return had
  }

  async check(indicator: string): Promise<Check> {
    return tc.check(indicator, await this.bearer(), this.o)
  }

  /** Hash a file here and ask about the hash: the file never leaves the machine. */
  async checkFile(path: string): Promise<Check> {
    const hash = createHash('sha256')
    for await (const chunk of Bun.file(path).stream()) hash.update(chunk)
    return tc.check(hash.digest('hex'), await this.bearer(), this.o)
  }

  private async need(): Promise<string> {
    const bearer = await this.bearer()
    if (!bearer) throw new AuthRequired('Not signed in. Run: securityagent login   (or set THREATCRUSH_API_KEY)')
    return bearer
  }
  async findings(args: { status?: string; severity?: string; limit?: number } = {}) {
    return tc.findings(await this.need(), args, this.o)
  }
  async incidents(args: { status?: string; host?: string; limit?: number } = {}) {
    return tc.incidents(await this.need(), args, this.o)
  }
  tools() {
    return tc.listTools(this.o)
  }
  /** Any ThreatCrush tool by name, as the signed-in person. */
  async call(name: string, args: Record<string, unknown> = {}): Promise<unknown> {
    return tc.callTool(name, args, await this.bearer(), this.o)
  }

  // ─── Desktops: through the security.agent site, which holds the tunnels ───

  readonly site = (process.env.SECAGENT_URL || 'https://security.agent.pit.world').replace(/\/+$/, '')

  private async siteJson<T>(path: string, init: RequestInit = {}): Promise<T> {
    const bearer = await this.need()
    let response: Response
    try {
      response = await (this.o.fetch ?? fetch)(`${this.site}${path}`, { ...init, headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json', ...(init.headers ?? {}) }, signal: AbortSignal.timeout(90_000) })
    } catch (e) {
      throw new tc.ThreatCrushError(`security.agent did not answer (${e instanceof Error ? e.message : String(e)}).`)
    }
    const body = (await response.json().catch(() => ({}))) as T & { error?: string }
    if (response.status === 401) throw new AuthRequired(body.error)
    if (!response.ok) throw new tc.ThreatCrushError(body.error ?? `security.agent answered HTTP ${response.status}.`, response.status)
    return body
  }
  /** Your desktops and whether each tunnel is up. */
  desktops() {
    return this.siteJson<{ desktops: { id: string; name: string; port: number; connected: boolean; state: string | null; error: string | null; seen_at: string | null }[]; tools: string[] }>('/api/v1/desktops')
  }
  /** One W3BS desktop tool on one of your desktops, through its tunnel. */
  async desktopCall(id: string, tool: string, args: Record<string, unknown> = {}): Promise<unknown> {
    return (await this.siteJson<{ result: unknown }>(`/api/v1/desktops/${encodeURIComponent(id)}/call`, { method: 'POST', body: JSON.stringify({ tool, arguments: args }) })).result
  }
}

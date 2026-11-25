/**
 * ThreatCrush, as security.agent uses it: an OAuth 2.1 client and an MCP caller.
 *
 * ThreatCrush is the authorization server (https://threatcrush.com): public
 * clients only, dynamic client registration (RFC 7591), the authorization code
 * grant with PKCE S256, rotating refresh tokens, one scope (`mcp`). An access
 * token works in exactly one place, the MCP resource at /api/mcp, and acts as
 * the person who approved it. So everything security.agent does for a signed-in
 * person is a tools/call there. A tc_agent_ key works as the Bearer too.
 *
 * Shared by the server, the CLI, the TUI and the stdio MCP server.
 */
import { createHash, randomBytes } from 'node:crypto'
import { isIP } from 'node:net'
import { VERSION } from './version.js'

export const THREATCRUSH = 'https://threatcrush.com'
export const SCOPE = 'mcp'
const UA = `securityagent/${VERSION} (+https://security.agent.pit.world)`

export type Tokens = { accessToken: string; refreshToken: string; expiresAt: number }
export type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>
export type TcOptions = { base?: string; fetch?: Fetch }

export class ThreatCrushError extends Error {
  constructor(message: string, readonly status = 502, readonly code = 'threatcrush_error') {
    super(message)
  }
}
/** The credential was refused, or there is none: sign in. */
export class AuthRequired extends ThreatCrushError {
  constructor(message = 'ThreatCrush wants you to sign in again.') {
    super(message, 401, 'auth_required')
  }
}

const baseOf = (o: TcOptions) => (o.base ?? THREATCRUSH).replace(/\/+$/, '')
export const mcpUrl = (o: TcOptions = {}) => `${baseOf(o)}/api/mcp`

// ─── OAuth 2.1 ───

export function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url')
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') }
}

async function json(response: Response): Promise<Record<string, unknown>> {
  try {
    const body = await response.json()
    return body && typeof body === 'object' ? (body as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}

/** Register a public client (RFC 7591). Returns its client_id. */
export async function registerClient(meta: { name: string; redirectUris: string[]; clientUri?: string; logoUri?: string }, o: TcOptions = {}): Promise<string> {
  const response = await (o.fetch ?? fetch)(`${baseOf(o)}/api/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': UA },
    body: JSON.stringify({
      client_name: meta.name,
      redirect_uris: meta.redirectUris,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: SCOPE,
      ...(meta.clientUri ? { client_uri: meta.clientUri } : {}),
      ...(meta.logoUri ? { logo_uri: meta.logoUri } : {}),
    }),
    signal: AbortSignal.timeout(15_000),
  })
  const body = await json(response)
  if (!response.ok || typeof body.client_id !== 'string') throw new ThreatCrushError(`ThreatCrush would not register the client: ${String(body.error_description ?? body.error ?? response.status)}`)
  return body.client_id
}

export function authorizeUrl(p: { clientId: string; redirectUri: string; state: string; challenge: string }, o: TcOptions = {}): string {
  const u = new URL(`${baseOf(o)}/oauth/authorize`)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('client_id', p.clientId)
  u.searchParams.set('redirect_uri', p.redirectUri)
  u.searchParams.set('code_challenge', p.challenge)
  u.searchParams.set('code_challenge_method', 'S256')
  u.searchParams.set('scope', SCOPE)
  u.searchParams.set('state', p.state)
  u.searchParams.set('resource', mcpUrl(o))
  return u.toString()
}

async function token(form: Record<string, string>, o: TcOptions): Promise<Tokens> {
  let response: Response
  try {
    response = await (o.fetch ?? fetch)(`${baseOf(o)}/api/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', 'user-agent': UA },
      body: new URLSearchParams(form).toString(),
      signal: AbortSignal.timeout(15_000),
    })
  } catch (e) {
    throw new ThreatCrushError(`ThreatCrush did not answer (${e instanceof Error ? e.message : String(e)}).`)
  }
  const body = await json(response)
  if (!response.ok || typeof body.access_token !== 'string' || typeof body.refresh_token !== 'string') {
    const why = String(body.error_description ?? body.error ?? `HTTP ${response.status}`)
    if (body.error === 'invalid_grant') throw new AuthRequired(why)
    throw new ThreatCrushError(`ThreatCrush did not issue a token: ${why}`)
  }
  const ttl = typeof body.expires_in === 'number' && body.expires_in > 0 ? body.expires_in : 3600
  return { accessToken: body.access_token, refreshToken: body.refresh_token, expiresAt: Date.now() + ttl * 1000 }
}

export const exchangeCode = (p: { code: string; verifier: string; clientId: string; redirectUri: string }, o: TcOptions = {}) =>
  token({ grant_type: 'authorization_code', code: p.code, code_verifier: p.verifier, client_id: p.clientId, redirect_uri: p.redirectUri }, o)

/** Refresh tokens rotate: the old one dies when this answers, so keep the new pair. */
export const refresh = (p: { refreshToken: string; clientId: string }, o: TcOptions = {}) => token({ grant_type: 'refresh_token', refresh_token: p.refreshToken, client_id: p.clientId }, o)

/** RFC 7009: ends the grant. Never throws. */
export async function revoke(tokenValue: string, o: TcOptions = {}): Promise<void> {
  await (o.fetch ?? fetch)(`${baseOf(o)}/api/oauth/revoke`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': UA },
    body: new URLSearchParams({ token: tokenValue }).toString(),
    signal: AbortSignal.timeout(10_000),
  }).catch(() => {})
}

// ─── MCP ───

let rpcId = 0

type Rpc = { result?: { content?: { type: string; text?: string }[]; isError?: boolean; tools?: unknown[] }; error?: { message?: string } }

async function rpc(method: string, params: Record<string, unknown>, bearer: string | null, o: TcOptions): Promise<NonNullable<Rpc['result']>> {
  let response: Response
  try {
    response = await (o.fetch ?? fetch)(mcpUrl(o), {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'user-agent': UA, ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
      signal: AbortSignal.timeout(30_000),
    })
  } catch (e) {
    throw new ThreatCrushError(`ThreatCrush did not answer (${e instanceof Error ? e.message : String(e)}).`)
  }
  if (response.status === 401) throw new AuthRequired()
  const status = response.status === 429 ? 429 : 502
  const body = (await json(response)) as Rpc
  if (body.error) throw new ThreatCrushError(body.error.message ?? 'ThreatCrush refused the request.', status)
  if (!response.ok || !body.result) throw new ThreatCrushError(`ThreatCrush answered HTTP ${response.status}.`, status)
  return body.result
}

/** One tools/call on ThreatCrush's MCP server. Returns the tool's JSON (or its text). */
export async function callTool<T = unknown>(name: string, args: Record<string, unknown>, bearer: string | null, o: TcOptions = {}): Promise<T> {
  const result = await rpc('tools/call', { name, arguments: args }, bearer, o)
  const text = (result.content ?? []).find((c) => c.type === 'text')?.text ?? ''
  if (result.isError) throw new ThreatCrushError(text || 'ThreatCrush refused the request.', 400, 'tool_error')
  try {
    return JSON.parse(text) as T
  } catch {
    return text as T
  }
}

export type ToolDef = { name: string; description?: string; inputSchema?: Record<string, unknown> }

/** ThreatCrush's own tool list (no credential needed). */
export const listTools = async (o: TcOptions = {}) => ((await rpc('tools/list', {}, null, o)).tools ?? []) as ToolDef[]

// ─── Indicators ───

export type Indicator = { kind: 'hash' | 'ip' | 'domain'; value: string }

const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/

/**
 * What did they paste? A SHA-256 (file reputation), an IP address, or a domain.
 * A URL or an email address is read as its host; defanged forms (hxxp, [.]) are
 * read as what they stand for. Anything else is null.
 */
export function parseIndicator(input: unknown): Indicator | null {
  let s = String(input ?? '').trim().toLowerCase()
  if (!s || s.length > 2048) return null
  if (/^[0-9a-f]{64}$/.test(s)) return { kind: 'hash', value: s }
  s = s.replace(/\[\.\]|\(\.\)/g, '.').replace(/^hxxp/, 'http')
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) {
    try {
      s = new URL(s).hostname
    } catch {
      return null
    }
  } else {
    if (s.includes('@')) s = s.slice(s.lastIndexOf('@') + 1)
    if (!isIP(s)) s = s.replace(/[/?#].*$/, '')
    if (!isIP(s) && /^[^:]+:\d{1,5}$/.test(s)) s = s.replace(/:\d+$/, '')
  }
  s = s.replace(/^\[|\]$/g, '').replace(/\.$/, '')
  if (isIP(s)) return { kind: 'ip', value: s }
  return DOMAIN.test(s) ? { kind: 'domain', value: s } : null
}

export type Verdict = 'malicious' | 'suspicious' | 'clean' | 'unknown'
export type Check = { indicator: string; kind: Indicator['kind']; verdict: Verdict; summary: string; score: number | null; details: Record<string, unknown> }

type HashHit = { knownMalicious?: string | null; malwareName?: string | null; trust?: number; fileName?: string | null }
type HashAnswer = { results?: Record<string, HashHit> }

/**
 * Check one indicator. A file hash needs no credential (CrushAV is open); an
 * IP or a domain needs one, and throws AuthRequired without it.
 */
export async function check(input: unknown, bearer: string | null, o: TcOptions = {}): Promise<Check> {
  const ind = parseIndicator(input)
  if (!ind) throw new ThreatCrushError('That is not an IP address, a domain, a URL or a SHA-256 file hash.', 400, 'bad_indicator')
  if (ind.kind === 'hash') {
    const answer = await callTool<HashAnswer>('av_hash_lookup', { hashes: [ind.value] }, bearer, o)
    const hit = answer?.results?.[ind.value]
    if (!hit) return { indicator: ind.value, kind: 'hash', verdict: 'unknown', summary: 'No source knows this file. Unknown is not the same as safe.', score: null, details: {} }
    if (hit.knownMalicious) {
      return { indicator: ind.value, kind: 'hash', verdict: 'malicious', summary: `Known malware${hit.malwareName ? ` (${hit.malwareName})` : ''}, listed by ${hit.knownMalicious}.`, score: 100, details: hit }
    }
    const trust = typeof hit.trust === 'number' ? hit.trust : 0
    return {
      indicator: ind.value,
      kind: 'hash',
      verdict: trust >= 50 ? 'clean' : 'unknown',
      summary: trust >= 50 ? `A published, known-good file${hit.fileName ? ` (${hit.fileName})` : ''}. Trust ${trust}/100.` : `Seen before${hit.fileName ? ` as ${hit.fileName}` : ''}, not listed as malware. Trust ${trust}/100.`,
      score: null,
      details: hit,
    }
  }
  if (!bearer) throw new AuthRequired('Sign in with ThreatCrush to check an IP address or a domain.')
  const r = await callTool<Record<string, unknown>>('reputation_lookup', { indicator: ind.value }, bearer, o)
  const details = r && typeof r === 'object' ? r : {}
  const listed = details.listed === true
  const score = typeof details.score === 'number' ? details.score : null
  const reported = (typeof details.reports === 'number' && details.reports > 0) || (score ?? 0) > 0
  const tail = score !== null ? ` Score ${score}/100.` : ''
  return {
    indicator: ind.value,
    kind: ind.kind,
    verdict: listed ? 'malicious' : reported ? 'suspicious' : 'clean',
    summary: listed ? `Listed: independent ThreatCrush servers blocked it.${tail}` : reported ? `Reported, but not enough reporters agree to list it.${tail}` : 'Not listed. No ThreatCrush server has reported it.',
    score,
    details,
  }
}

export type Finding = { id: string; title?: string; severity?: string; status?: string; source?: string; [k: string]: unknown }
export type Incident = { id: string; title?: string; severity?: string; status?: string; host?: string; [k: string]: unknown }

const listOf = <T>(value: unknown, key: string): T[] => {
  if (Array.isArray(value)) return value as T[]
  const inner = (value as Record<string, unknown> | null)?.[key]
  return Array.isArray(inner) ? (inner as T[]) : []
}

/**
 * The ThreatCrush user id behind a credential. The `mcp` scope has no userinfo
 * endpoint; list_invites is the read-only tool that names the caller. A tc_agent_
 * key belongs to a team, not a person, so it has none (null).
 */
export async function whoami(bearer: string, o: TcOptions = {}): Promise<string | null> {
  try {
    const r = await callTool<{ userId?: unknown }>('list_invites', {}, bearer, o)
    return typeof r?.userId === 'string' && r.userId ? r.userId : null
  } catch (e) {
    if (e instanceof AuthRequired) throw e
    return null
  }
}

export const findings = async (bearer: string, args: { status?: string; severity?: string; limit?: number } = {}, o: TcOptions = {}) =>
  listOf<Finding>(await callTool('findings_list', { limit: 25, ...args }, bearer, o), 'findings')

export const incidents = async (bearer: string, args: { status?: string; host?: string; limit?: number } = {}, o: TcOptions = {}) =>
  listOf<Incident>(await callTool('incidents_list', { limit: 25, ...args }, bearer, o), 'incidents')

/**
 * A stand-in for threatcrush.com: dynamic registration, the authorization code
 * grant with PKCE S256, rotating refresh tokens, revocation, and the MCP tools
 * security.agent calls. In memory, as a fetch function.
 */
import { createHash } from 'node:crypto'

/** A made-up AWS-shaped key, built at run time so secret scanners do not flag the source. */
export const FAKE_AWS = ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join('')

export type FakeTc = {
  fetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response>
  /** Approve a pending authorization: returns the code ThreatCrush would redirect with. */
  approve(clientId: string, redirectUri: string, challenge: string): string
  clients: Map<string, string[]>
  access: Set<string>
  refresh: Set<string>
  revoked: string[]
  calls: { name: string; args: Record<string, unknown>; bearer: string | null }[]
  userId: string
}

export function fakeThreatCrush(base = 'https://tc.test'): FakeTc {
  let n = 0
  const codes = new Map<string, { clientId: string; redirectUri: string; challenge: string }>()
  const tc: FakeTc = {
    clients: new Map(),
    access: new Set(),
    refresh: new Set(),
    revoked: [],
    calls: [],
    userId: 'user-123',
    approve(clientId, redirectUri, challenge) {
      const code = `code_${++n}`
      codes.set(code, { clientId, redirectUri, challenge })
      return code
    },
    async fetch(input, init) {
      const url = new URL(String(input instanceof Request ? input.url : input))
      if (url.origin !== base) return new Response('no route to host', { status: 599 })
      const body = typeof init?.body === 'string' ? init.body : ''
      const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } })
      if (url.pathname === '/api/oauth/register') {
        const meta = JSON.parse(body) as { redirect_uris: string[] }
        const id = `tc_client_${++n}`
        tc.clients.set(id, meta.redirect_uris)
        return json({ client_id: id }, 201)
      }
      if (url.pathname === '/api/oauth/token') {
        const p = Object.fromEntries(new URLSearchParams(body))
        const pair = () => {
          const a = `tc_oat_${++n}`
          const r = `tc_ort_${++n}`
          tc.access.add(a)
          tc.refresh.add(r)
          return json({ access_token: a, refresh_token: r, token_type: 'Bearer', expires_in: 3600, scope: 'mcp' })
        }
        if (p.grant_type === 'authorization_code') {
          const c = codes.get(p.code ?? '')
          codes.delete(p.code ?? '')
          if (!c || c.clientId !== p.client_id || c.redirectUri !== p.redirect_uri) return json({ error: 'invalid_grant', error_description: 'bad code' }, 400)
          if (createHash('sha256').update(p.code_verifier ?? '').digest('base64url') !== c.challenge) return json({ error: 'invalid_grant', error_description: 'PKCE' }, 400)
          return pair()
        }
        if (p.grant_type === 'refresh_token') {
          if (!tc.refresh.delete(p.refresh_token ?? '')) return json({ error: 'invalid_grant', error_description: 'refresh token already used' }, 400)
          return pair()
        }
        return json({ error: 'unsupported_grant_type' }, 400)
      }
      if (url.pathname === '/api/oauth/revoke') {
        const p = Object.fromEntries(new URLSearchParams(body))
        tc.revoked.push(p.token ?? '')
        tc.refresh.delete(p.token ?? '')
        return new Response(null, { status: 200 })
      }
      if (url.pathname === '/api/mcp') {
        const msg = JSON.parse(body) as { id: number; method: string; params: { name: string; arguments: Record<string, unknown> } }
        const auth = new Headers(init?.headers).get('authorization')
        const bearer = auth?.replace(/^Bearer /, '') ?? null
        const ok = (v: unknown) => json({ jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: JSON.stringify(v) }] } })
        if (msg.method === 'tools/list') return json({ jsonrpc: '2.0', id: msg.id, result: { tools: [{ name: 'av_hash_lookup', description: 'hashes' }, { name: 'reputation_lookup', description: 'ips' }] } })
        const { name, arguments: args } = msg.params
        tc.calls.push({ name, args, bearer })
        if (name === 'av_hash_lookup') {
          const h = (args.hashes as string[])[0]!
          if (h.startsWith('275a')) return ok({ checked: 1, known: 1, results: { [h]: { sha256: h, knownMalicious: 'malshare.com', malwareName: null, trust: 0, fileName: 'eicar.com' } } })
          return ok({ checked: 1, known: 0, results: {} })
        }
        const valid = bearer && (tc.access.has(bearer) || bearer.startsWith('tc_agent_'))
        if (!valid) return new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401, headers: { 'www-authenticate': 'Bearer' } })
        if (name === 'reputation_lookup') {
          const ind = String(args.indicator)
          if (ind === '203.0.113.9') return ok({ indicator: ind, listed: true, score: 92, severity: 'high', reports: 40, reporters: 7, country: 'NL', rules: ['ssh-brute-force'] })
          return ok({ indicator: ind, listed: false, score: 0, reports: 0 })
        }
        if (name === 'findings_list') return ok({ findings: [{ id: 'f1', severity: 'high', status: 'open', source: 'scan', type: 'secret', message: `AWS key ${FAKE_AWS} in config.js` }], total: 1 })
        if (name === 'incidents_list') return ok({ incidents: [{ id: 'i1', severity: 'critical', status: 'open', title: 'SSH login from Tor', host: 'web1' }] })
        if (name === 'list_invites') return bearer!.startsWith('tc_agent_') ? json({ jsonrpc: '2.0', id: msg.id, result: { isError: true, content: [{ type: 'text', text: 'Session token only' }] } }) : ok({ userId: tc.userId, remaining: 3 })
        return json({ jsonrpc: '2.0', id: msg.id, result: { isError: true, content: [{ type: 'text', text: `unknown tool ${name}` }] } })
      }
      return new Response('not found', { status: 404 })
    },
  }
  return tc
}

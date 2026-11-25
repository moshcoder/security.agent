import { afterAll, beforeEach, describe, expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { redact } from '../src/analyst.ts'
import { Sealer, Store } from '../src/db.ts'
import { brokerCall, parsePublicKey, setupScript } from '../src/desktops.ts'
import { createApp } from '../src/server.ts'
import { parseIndicator } from '../src/threatcrush.ts'
import { FAKE_AWS, fakeThreatCrush, type FakeTc } from './fake-threatcrush.ts'

const KEY = 'k'.repeat(32)
const PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7x5mGv1h0Qe0a2l5bWZQJ0vX8yq6l9y2b1oQ3eZJ3y security-agent-tunnel'
const PUB2 = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1y5mGv1h0Qe0a2l5bWZQJ0vX8yq6l9y2b1oQ3eZJ3z other'
const TMP = mkdtempSync(join(tmpdir(), 'secagent-test-'))

type App = ReturnType<typeof createApp>
let tc: FakeTc
let app: App
let generated: { system: string; user: string }[]
let brokerCalls: { tool: string; args: Record<string, unknown> }[]

const make = (keysFile?: string) => {
  tc = fakeThreatCrush()
  generated = []
  brokerCalls = []
  const store = new Store(':memory:', new Sealer(KEY))
  app = createApp({
    store,
    key: KEY,
    secureCookies: false,
    config: { threatcrush: 'https://tc.test', fetch: tc.fetch, tunnelHost: 'tunnel.test', ...(keysFile ? { tunnelKeysFile: keysFile } : {}) },
    generate: async (req) => (generated.push(req), { text: 'Block it. Then run ThreatCrush on your servers.', model: 'qwen3:4b', provider: 'c0mpute' }),
    broker: async (_d, token, tool, args) => {
      brokerCalls.push({ tool, args })
      if (token !== 'agent-token-0123456789') throw new Error('bad token')
      return { content: [{ type: 'text', text: JSON.stringify({ state: 'enabled' }) }] }
    },
  })
  return app
}

const req = (path: string, init: RequestInit & { cookie?: string } = {}) =>
  app.request(`https://security.agent.pit.world${path}`, { ...init, headers: { 'x-moshpit-name': 'security.agent', ...(init.cookie ? { cookie: init.cookie } : {}), ...(init.headers ?? {}) } })

const form = (fields: Record<string, string>) => ({ method: 'POST', body: new URLSearchParams(fields), headers: { 'content-type': 'application/x-www-form-urlencoded' } })

/** The whole browser sign-in: start, approve at the fake ThreatCrush, callback. Returns the session cookie. */
async function signIn(): Promise<string> {
  const start = await req('/auth/start')
  expect(start.status).toBe(302)
  const auth = new URL(start.headers.get('location')!)
  expect(auth.origin + auth.pathname).toBe('https://tc.test/oauth/authorize')
  expect(auth.searchParams.get('code_challenge_method')).toBe('S256')
  expect(auth.searchParams.get('scope')).toBe('mcp')
  expect(auth.searchParams.get('resource')).toBe('https://tc.test/api/mcp')
  const code = tc.approve(auth.searchParams.get('client_id')!, auth.searchParams.get('redirect_uri')!, auth.searchParams.get('code_challenge')!)
  const back = await req(`/auth/callback?code=${code}&state=${auth.searchParams.get('state')}&iss=https://tc.test`)
  expect(back.status).toBe(302)
  expect(back.headers.get('location')).toBe('/me')
  const cookie = back.headers.get('set-cookie')!.split(';')[0]!
  expect(cookie.startsWith('sa_session=')).toBe(true)
  return cookie
}

const csrfFrom = async (cookie: string, path = '/desktops') => /name="csrf" value="([0-9a-f]{32})"/.exec(await (await req(path, { cookie })).text())![1]!

beforeEach(() => make())

describe('indicators', () => {
  test('reads IPs, domains, URLs, emails, defanged forms and hashes', () => {
    expect(parseIndicator('203.0.113.9')).toEqual({ kind: 'ip', value: '203.0.113.9' })
    expect(parseIndicator('[2001:db8::1]')).toEqual({ kind: 'ip', value: '2001:db8::1' })
    expect(parseIndicator('https://Evil.Example.com/login?x=1')).toEqual({ kind: 'domain', value: 'evil.example.com' })
    expect(parseIndicator('hxxps://evil[.]example[.]com/a')).toEqual({ kind: 'domain', value: 'evil.example.com' })
    expect(parseIndicator('bob@phish.example')).toEqual({ kind: 'domain', value: 'phish.example' })
    expect(parseIndicator('example.com:8443')).toEqual({ kind: 'domain', value: 'example.com' })
    expect(parseIndicator('A'.repeat(64))).toEqual({ kind: 'hash', value: 'a'.repeat(64) })
    expect(parseIndicator('not a thing')).toBeNull()
    expect(parseIndicator('localhost')).toBeNull()
  })
})

describe('pages', () => {
  test('home names all three engines and the two-way tunnel', async () => {
    const html = await (await req('/')).text()
    for (const s of ['ThreatCrush', 'c0mpute', 'W3BS desktop', 'one outbound SSH connection', 'dev2', 'bonita', 'Sign in with ThreatCrush']) expect(html).toContain(s)
    expect(html).toContain('ring/profullstack')
    expect(html).not.toContain('data-cp-ad')
  })
  test('connect, llms.txt, robots and security headers', async () => {
    const r = await req('/connect')
    expect(r.headers.get('content-security-policy')).toContain("frame-ancestors 'none'")
    const html = await r.text()
    expect(html).toContain('claude mcp add --transport http threatcrush https://threatcrush.com/api/mcp')
    expect(html).toContain('/api/v1/desktops')
    const llms = await (await req('/llms.txt')).text()
    expect(llms).toContain('c0mpute')
    expect(llms).toContain('w3bs.org/desktop')
    expect(await (await req('/robots.txt')).text()).toContain('Disallow: /desktops')
  })
  test('/go counts and tags the way out', async () => {
    const r = await req('/go/install')
    expect(r.headers.get('location')).toBe('https://threatcrush.com/?utm_source=security.agent&utm_medium=referral&utm_campaign=install#install')
    expect((await req('/go/nope')).headers.get('location')).toBe('/')
  })
})

describe('checks', () => {
  test('a file hash needs no sign-in', async () => {
    const r = await req('/api/v1/check?q=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
    expect(r.status).toBe(200)
    const j = (await r.json()) as { verdict: string; summary: string }
    expect(j.verdict).toBe('malicious')
    expect(j.summary).toContain('malshare.com')
    expect(tc.calls[0]!.bearer).toBeNull()
  })
  test('an IP without a credential is 401 with where to sign in', async () => {
    const r = await req('/api/v1/check?q=203.0.113.9')
    expect(r.status).toBe(401)
    const j = (await r.json()) as { sign_in: string; mcp: string }
    expect(j.sign_in).toBe('https://security.agent.pit.world/auth/start')
    expect(j.mcp).toBe('https://tc.test/api/mcp')
  })
  test('a caller Bearer is passed through, and explain=1 asks c0mpute', async () => {
    const r = await req('/api/v1/check?q=203.0.113.9&explain=1', { headers: { authorization: 'Bearer tc_agent_abcdef123456' } })
    const j = (await r.json()) as { verdict: string; score: number; analysis: { text: string; provider: string } }
    expect(j.verdict).toBe('malicious')
    expect(j.score).toBe(92)
    expect(j.analysis.provider).toBe('c0mpute')
    expect(generated[0]!.user).toContain('203.0.113.9')
    expect(tc.calls.at(-1)!.bearer).toBe('tc_agent_abcdef123456')
  })
  test('no explain, no c0mpute call', async () => {
    await req('/api/v1/check?q=203.0.113.9', { headers: { authorization: 'Bearer tc_agent_abcdef123456' } })
    expect(generated.length).toBe(0)
  })
  test('the web form: hash for anyone, IP asks to sign in', async () => {
    const h = await (await req('/check', form({ q: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', explain: '1' }))).text()
    expect(h).toContain('Malicious')
    expect(h).toContain('Analyst')
    const ip = await req('/check', form({ q: '203.0.113.9' }))
    expect(ip.status).toBe(401)
    expect(await ip.text()).toContain('/auth/start?q=203.0.113.9')
  })
})

describe('sign in with ThreatCrush', () => {
  test('registers once, signs in, learns who, shows the dashboard', async () => {
    const cookie = await signIn()
    expect(tc.clients.size).toBe(1)
    expect([...tc.clients.values()][0]).toEqual(['https://security.agent/auth/callback', 'https://security.agent.pit.world/auth/callback'])
    await signIn()
    expect(tc.clients.size).toBe(1)
    const me = await (await req('/me', { cookie })).text()
    expect(me).toContain('SSH login from Tor')
    expect(me).toContain('AWS key')
    expect(me).toContain('What should I fix first?')
    expect(generated.length).toBe(0)
    expect(tc.calls.some((c) => c.name === 'list_invites')).toBe(true)
  })
  test('a code from another issuer is refused', async () => {
    const start = new URL((await req('/auth/start')).headers.get('location')!)
    const code = tc.approve(start.searchParams.get('client_id')!, start.searchParams.get('redirect_uri')!, start.searchParams.get('code_challenge')!)
    const r = await req(`/auth/callback?code=${code}&state=${start.searchParams.get('state')}&iss=https://evil.test`)
    expect(r.status).toBe(400)
  })
  test('a state is single use', async () => {
    const start = new URL((await req('/auth/start')).headers.get('location')!)
    const code = tc.approve(start.searchParams.get('client_id')!, start.searchParams.get('redirect_uri')!, start.searchParams.get('code_challenge')!)
    await req(`/auth/callback?code=${code}&state=${start.searchParams.get('state')}`)
    expect((await req(`/auth/callback?code=${code}&state=${start.searchParams.get('state')}`)).status).toBe(400)
  })
  test('signed in, an IP check uses the session grant', async () => {
    const cookie = await signIn()
    const r = await req('/api/v1/check?q=203.0.113.9', { cookie })
    expect(r.status).toBe(200)
    expect(tc.access.has(tc.calls.at(-1)!.bearer!)).toBe(true)
  })
  test('the brief sends redacted data to c0mpute only when asked', async () => {
    const cookie = await signIn()
    const csrf = await csrfFrom(cookie, '/me')
    const html = await (await req('/me/brief', { ...form({ csrf }), cookie })).text()
    expect(html).toContain('Block it.')
    expect(generated.length).toBe(1)
    expect(generated[0]!.user).toContain('SSH login from Tor')
    expect(generated[0]!.user).not.toContain(FAKE_AWS)
  })
  test('sign out revokes the grant at ThreatCrush', async () => {
    const cookie = await signIn()
    const csrf = await csrfFrom(cookie, '/me')
    await req('/auth/logout', { ...form({ csrf }), cookie })
    expect(tc.revoked.length).toBe(1)
    expect((await req('/me', { cookie })).headers.get('location')).toBe('/auth/start')
  })
})

describe('desktops', () => {
  test('add, list live, call through the broker, remove; keys file follows', async () => {
    const keys = join(TMP, `keys-${Date.now()}`)
    make(keys)
    const cookie = await signIn()
    const csrf = await csrfFrom(cookie)
    const added = await req('/desktops', { ...form({ csrf, name: 'bonita', public_key: PUB, token: 'agent-token-0123456789' }), cookie })
    expect(added.status).toBe(200)
    const html = await added.text()
    expect(html).toContain('Connected')
    expect(html).toContain('-R localhost:')
    expect(html).toContain('secagent-tunnel@tunnel.test')
    const line = readFileSync(keys, 'utf8')
    expect(line).toMatch(/^restrict,port-forwarding,permitlisten="localhost:2\d{4}",command="\/bin\/false" ssh-ed25519 AAAA\S+ security-agent-dt_/)
    expect(line).not.toContain('agent-token')

    const list = (await (await req('/api/v1/desktops', { cookie })).json()) as { desktops: { id: string; connected: boolean; state: string }[] }
    expect(list.desktops[0]!.connected).toBe(true)
    expect(list.desktops[0]!.state).toBe('enabled')
    const id = list.desktops[0]!.id
    const call = await req(`/api/v1/desktops/${id}/call`, { method: 'POST', cookie, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tool: 'desktop_screenshot', arguments: {} }) })
    expect(call.status).toBe(200)
    expect(brokerCalls.at(-1)!.tool).toBe('desktop_screenshot')
    const bad = await req(`/api/v1/desktops/${id}/call`, { method: 'POST', cookie, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tool: 'shell_exec' }) })
    expect(bad.status).toBe(400)

    // sshd's AuthorizedKeysCommand passes the app's line through, only for the tunnel user,
    // and drops anything that is not exactly that shape.
    const sshd = (user: string, file: string) => Bun.spawnSync(['sh', 'deploy/tunnel/authorized-keys', user], { env: { SECAGENT_TUNNEL_KEYS_TEST: file } }).stdout.toString()
    expect(sshd('secagent-tunnel', keys)).toBe(line)
    expect(sshd('root', keys)).toBe('')
    const evil = join(TMP, `evil-${Date.now()}`)
    await Bun.write(evil, `${line}ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7x5mGv1h0Qe0a2l5bWZQJ0vX8yq6l9y2b1oQ3eZJ3y no-restrictions\nrestrict,port-forwarding,permitlisten="localhost:22",command="/bin/false" ${PUB2.split(' ').slice(0, 2).join(' ')} security-agent-dt_x\n`)
    expect(sshd('secagent-tunnel', evil)).toBe(line)

    await req(`/desktops/${id}/delete`, { ...form({ csrf }), cookie })
    expect(readFileSync(keys, 'utf8')).toBe('')
  })
  test('a Bearer from the same person sees the same desktops; an agent key does not', async () => {
    const cookie = await signIn()
    const csrf = await csrfFrom(cookie)
    await req('/desktops', { ...form({ csrf, name: 'laptop', public_key: PUB, token: 'agent-token-0123456789' }), cookie })
    const access = [...tc.access].at(-1)!
    const mine = (await (await req('/api/v1/desktops', { headers: { authorization: `Bearer ${access}` } })).json()) as { desktops: unknown[] }
    expect(mine.desktops.length).toBe(1)
    const agent = await req('/api/v1/desktops', { headers: { authorization: 'Bearer tc_agent_abcdef123456' } })
    expect(agent.status).toBe(403)
  })
  test('another person cannot see or call my desktop', async () => {
    const cookie = await signIn()
    const csrf = await csrfFrom(cookie)
    await req('/desktops', { ...form({ csrf, name: 'laptop', public_key: PUB, token: 'agent-token-0123456789' }), cookie })
    const id = ((await (await req('/api/v1/desktops', { cookie })).json()) as { desktops: { id: string }[] }).desktops[0]!.id
    tc.userId = 'user-456'
    const other = await signIn()
    expect(((await (await req('/api/v1/desktops', { cookie: other })).json()) as { desktops: unknown[] }).desktops.length).toBe(0)
    const call = await req(`/api/v1/desktops/${id}/call`, { method: 'POST', cookie: other, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tool: 'desktop_status' }) })
    expect(call.status).toBe(404)
  })
  test('refuses a bad key, a reused key, a short token, a stale form', async () => {
    const cookie = await signIn()
    const csrf = await csrfFrom(cookie)
    expect((await req('/desktops', { ...form({ csrf, public_key: 'hello', token: 'agent-token-0123456789' }), cookie })).status).toBe(400)
    expect((await req('/desktops', { ...form({ csrf, public_key: PUB, token: 'short' }), cookie })).status).toBe(400)
    expect((await req('/desktops', { ...form({ csrf, public_key: PUB, token: 'agent-token-0123456789' }), cookie })).status).toBe(200)
    expect((await req('/desktops', { ...form({ csrf, public_key: PUB, token: 'agent-token-0123456789' }), cookie })).status).toBe(400)
    expect((await req('/desktops', { ...form({ csrf: 'x', public_key: PUB2, token: 'agent-token-0123456789' }), cookie })).status).toBe(400)
  })
  test('parsePublicKey drops options and comments, refuses mismatched blobs', () => {
    expect(parsePublicKey(`command="rm -rf /" ${PUB}`)).toBe(PUB.split(' ').slice(0, 2).join(' '))
    expect(() => parsePublicKey(`ssh-rsa ${PUB.split(' ')[1]}`)).toThrow()
  })
  test('the setup script opens one reverse tunnel to the broker', () => {
    const s = setupScript({ port: 21234, brokerPort: 7801 }, 'dev2.profullstack.com')
    expect(s).toContain('-R localhost:21234:127.0.0.1:7801 secagent-tunnel@dev2.profullstack.com')
    expect(s).toContain('ExitOnForwardFailure=yes')
    expect(s).toContain('w3bs desktop agents add security-agent')
  })
})

describe('the broker client, over a real loopback "tunnel"', () => {
  // A stand-in broker that enforces what the real one does: its own Host, no Origin, a bearer, sessions.
  const seen: { host: string | null; origin: string | null }[] = []
  const fake = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    async fetch(request) {
      seen.push({ host: request.headers.get('host'), origin: request.headers.get('origin') })
      if (request.headers.get('host') !== '127.0.0.1:7801' || request.headers.get('origin')) return new Response('wrong host', { status: 421 })
      if (request.headers.get('authorization') !== 'Bearer tok-1234567890abcdef') return new Response('{}', { status: 401 })
      const msg = (await request.json()) as { id?: number; method: string; params?: { name: string } }
      if (msg.method === 'initialize') return Response.json({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-06-18' } }, { headers: { 'mcp-session-id': 's1' } })
      if (request.headers.get('mcp-session-id') !== 's1') return new Response('{}', { status: 400 })
      if (!msg.id) return new Response(null, { status: 202 })
      return Response.json({ jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: JSON.stringify({ tool: msg.params?.name, state: 'enabled' }) }] } })
    },
  })
  afterAll(() => fake.stop(true))
  const desktop = { id: 'dt_test12345', owner: 'u', name: 'x', publicKey: PUB, port: fake.port!, brokerPort: 7801, createdAt: 0, seenAt: null }

  test('sends the broker its own Host, no Origin, and keeps the session', async () => {
    const r = (await brokerCall(desktop, 'tok-1234567890abcdef', 'desktop_status', {})) as { content: { text: string }[] }
    expect(JSON.parse(r.content[0]!.text)).toEqual({ tool: 'desktop_status', state: 'enabled' })
    expect(seen.every((s) => s.host === '127.0.0.1:7801' && s.origin === null)).toBe(true)
    const before = seen.length
    await brokerCall(desktop, 'tok-1234567890abcdef', 'desktop_windows', {})
    expect(seen.length).toBe(before + 1)
  })
  test('a wrong token says so', async () => {
    await expect(brokerCall({ ...desktop, id: 'dt_other12345' }, 'nope-nope-nope-nope', 'desktop_status', {})).rejects.toThrow(/refused our agent token/)
  })
  test('a tunnel that is down says so', async () => {
    await expect(brokerCall({ ...desktop, id: 'dt_down123456', port: 1 }, 'tok-1234567890abcdef', 'desktop_status', {})).rejects.toThrow(/tunnel is down/)
  })
})

describe('redact', () => {
  test('strips keys, tokens, passwords and emails, keeps hashes', () => {
    const h = createHash('sha256').update('x').digest('hex')
    const out = redact(`key ${FAKE_AWS} token=tc_agent_abcdefghijk password: hunter22 mail bob@example.com hash ${h}`)
    expect(out).not.toContain(FAKE_AWS)
    expect(out).not.toContain('tc_agent_abcdefghijk')
    expect(out).not.toContain('hunter22')
    expect(out).not.toContain('bob@example.com')
    expect(out).toContain(h)
  })
})

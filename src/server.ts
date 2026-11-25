/**
 * The security.agent web server: pages, the JSON API and Sign in with ThreatCrush.
 *
 * security.agent is a Moshpit name. Visitors on Moshpit DNS reach
 * https://security.agent directly; everyone else comes through the pit.world
 * relay at https://security.agent.pit.world, which says so with an
 * x-moshpit-name header. Links, cookies and the OAuth callback follow whichever
 * one the visitor used.
 *
 * It is a funnel to ThreatCrush, with three engines under the hood:
 *   - ThreatCrush supplies every fact, through its MCP server, called with the
 *     grant the visitor approved (OAuth 2.1, PKCE, public client) or with the
 *     credential an API caller sent (passed through, never stored).
 *   - c0mpute writes the analysis (src/analyst.ts): what a result means, what to
 *     fix first. Open models on the peer network; never a paid model.
 *   - W3BS desktops (src/desktops.ts) are for work that has to happen on the
 *     person's own computer, reached through a tunnel their desktop opens.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { Hono, type Context } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { analystEnabled, brief, explainCheck, type Analysis, type Generate } from './analyst.js'
import { Sealer, Store } from './db.js'
import { brokerCall, DESKTOP_TOOLS, DesktopError, Desktops, setupScript, type BrokerCall, type Desktop } from './desktops.js'
import { connectPage, dashboardPage, desktopsPage, homePage, llmsTxt, messagePage, type Ctx } from './html.js'
import { startPitFooterRefresh } from './pit-footer.js'
import { FOOTER_SCRIPT_SRC, ringDescriptor, startRingFooterRefresh } from './ring-footer.js'
import { RING_PLACEHOLDER, ringBar, startRingRefresh, visitorOnMoshpit } from './ring.js'
import * as tc from './threatcrush.js'
import { AuthRequired, ThreatCrushError, type Check, type Fetch, type ToolDef } from './threatcrush.js'
import { VERSION } from './version.js'

export { VERSION }

const SELF = 'security.agent'
const DIRECT_ORIGIN = 'https://security.agent'
const RELAY_ORIGIN = 'https://security.agent.pit.world'
const SESSION = 'sa_session'
const CLIENT_KEY = 'tc_client_id'

const SECURITY_HEADERS: Record<string, string> = {
  'content-security-policy': `default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' https://crawlproof.com https://cdn.jsdelivr.net ${FOOTER_SCRIPT_SRC}; img-src 'self' data: https://built.indie.pit.world https://pwamart.com https://saasrow.pwa.pit.world https://profullstack.com; connect-src 'self' https://crawlproof.com https://pit.world; frame-src https://crawlproof.com; manifest-src 'self'; form-action 'self' https://pit.world; base-uri 'none'; frame-ancestors 'none'`,
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-content-type-options': 'nosniff',
  'permissions-policy': 'interest-cohort=(), browsing-topics=(), camera=(), microphone=(), geolocation=()',
  'cross-origin-opener-policy': 'same-origin',
}

/** Where the calls to action go. Each is counted, so the funnel can be read from /api/v1/stats. */
const GO: Record<string, string> = {
  threatcrush: 'https://threatcrush.com/',
  install: 'https://threatcrush.com/#install',
  pricing: 'https://threatcrush.com/pricing',
  antivirus: 'https://threatcrush.com/antivirus',
  dashboard: 'https://threatcrush.com/account',
  docs: 'https://threatcrush.com/docs',
  w3bs: 'https://w3bs.org/desktop',
  c0mpute: 'https://c0mpute.com/',
}

export type Config = {
  /** The ThreatCrush origin (the OAuth authorization server and the MCP resource). */
  threatcrush?: string
  /** A pre-registered OAuth client id; without one the app registers itself once and remembers it. */
  clientId?: string
  /** Bearer for /api/v1/stats. */
  adminKey?: string
  /** The host desktops open their tunnel to (`ssh -R ... secagent-tunnel@<this>`). */
  tunnelHost?: string
  tunnelUser?: string
  /** Where the desktops' restricted authorized_keys lines are written for sshd. */
  tunnelKeysFile?: string
  fetch?: Fetch
}
export type Deps = { store: Store; key: string; config?: Config; secureCookies?: boolean; generate?: Generate; broker?: BrokerCall }

type Env = { Bindings: { ip?: string } }

/** A small fixed-window limit per key, in memory: enough to stop a loop, not a fortress. */
class Limiter {
  private hits = new Map<string, { n: number; reset: number }>()
  constructor(private readonly max: number, private readonly windowMs: number) {}
  allow(key: string, now = Date.now()): boolean {
    const h = this.hits.get(key)
    if (!h || h.reset < now) {
      if (this.hits.size > 50_000) this.hits.clear()
      this.hits.set(key, { n: 1, reset: now + this.windowMs })
      return true
    }
    h.n += 1
    return h.n <= this.max
  }
}

type CheckOut = { q: string; result?: Check; analysis?: Analysis | null; error?: string; needSignIn?: boolean; status: number }

export function createApp(deps: Deps) {
  const { store } = deps
  const config = deps.config ?? {}
  const tco = { ...(config.threatcrush ? { base: config.threatcrush } : {}), ...(config.fetch ? { fetch: config.fetch } : {}) }
  const app = new Hono<Env>()
  const desktops = new Desktops(store.db, store.sealer, config.tunnelKeysFile ?? null)
  const broker = deps.broker ?? brokerCall
  const tunnelHost = config.tunnelHost ?? 'dev2.profullstack.com'
  const tunnelUser = config.tunnelUser ?? 'secagent-tunnel'
  const openLimit = new Limiter(30, 10 * 60_000)
  const userLimit = new Limiter(120, 10 * 60_000)
  const authLimit = new Limiter(30, 10 * 60_000)
  const aiLimit = new Limiter(20, 10 * 60_000)
  const desktopLimit = new Limiter(600, 10 * 60_000)

  const direct = (c: Context) => visitorOnMoshpit(SELF, c.req.header('host'), c.req.header('x-moshpit-name'))
  // nginx serves the Moshpit name on port 80 too, for clients that cannot check its certificate.
  const https = (c: Context) => (c.req.header('x-forwarded-proto') ?? 'https') === 'https'
  const origin = (c: Context) => (direct(c) && https(c) ? DIRECT_ORIGIN : RELAY_ORIGIN)
  const ip = (c: Context<Env>) => c.env?.ip ?? 'local'
  const sessionId = (c: Context) => getCookie(c, SESSION)
  const csrfFor = (sid: string | undefined) => (sid ? createHmac('sha256', deps.key).update(`csrf:${sid}`).digest('hex').slice(0, 32) : '')
  const signedIn = (c: Context) => store.session(sessionId(c)) !== null
  const ctxOf = (c: Context): Ctx => ({ signedIn: signedIn(c), origin: origin(c), csrf: csrfFor(sessionId(c)) })
  const csrfOk = (c: Context, given: unknown) => {
    const expected = csrfFor(sessionId(c))
    const g = Buffer.from(String(given ?? ''))
    const e = Buffer.from(expected)
    return expected !== '' && g.length === e.length && timingSafeEqual(g, e)
  }
  const page = (c: Context, html: string, status = 200) => c.html(html.replace(RING_PLACEHOLDER, ringBar(SELF, direct(c))), status as 200)
  const keyed = (value: string) => createHmac('sha256', deps.key).update(value).digest('hex').slice(0, 32)

  // The OAuth client ThreatCrush knows us as: configured, remembered, or registered now (once).
  let registering: Promise<string> | null = null
  const clientId = (): Promise<string> => {
    const known = config.clientId ?? store.get(CLIENT_KEY)
    if (known) return Promise.resolve(known)
    registering ??= tc
      .registerClient({ name: 'security.agent', redirectUris: [`${DIRECT_ORIGIN}/auth/callback`, `${RELAY_ORIGIN}/auth/callback`], clientUri: RELAY_ORIGIN, logoUri: `${RELAY_ORIGIN}/icon-512.png` }, tco)
      .then((id) => (store.set(CLIENT_KEY, id), id))
      .finally(() => (registering = null))
    return registering
  }

  // A session's access token, refreshed when it is about to lapse. Refresh tokens
  // rotate, so two requests must never refresh the same session at once.
  const refreshing = new Map<string, Promise<string>>()
  const bearerOf = async (sid: string | undefined): Promise<string | null> => {
    const session = store.session(sid)
    if (!sid || !session) return null
    if (session.tokens.expiresAt - 60_000 > Date.now()) return session.tokens.accessToken
    let pending = refreshing.get(sid)
    if (!pending) {
      pending = tc
        .refresh({ refreshToken: session.tokens.refreshToken, clientId: session.clientId }, tco)
        .then((tokens) => (store.saveTokens(sid, tokens), tokens.accessToken))
        .finally(() => refreshing.delete(sid))
      refreshing.set(sid, pending)
    }
    try {
      return await pending
    } catch (e) {
      // The grant is gone (revoked at ThreatCrush, or the refresh token expired): the session is over.
      if (e instanceof AuthRequired) store.endSession(sid)
      throw e
    }
  }

  const givenBearer = (c: Context) => /^Bearer\s+(\S{8,512})$/i.exec(c.req.header('authorization') ?? '')?.[1]

  /** The credential for an API request: the caller's own Bearer, else their session. */
  const credential = async (c: Context): Promise<string | null> => givenBearer(c) ?? (await bearerOf(sessionId(c)))

  // Who the caller is at ThreatCrush: desktops belong to that account. A session learned it at
  // sign-in; a bare Bearer is asked once and remembered for ten minutes (by an HMAC, never the token).
  const owners = new Map<string, { sub: string | null; at: number }>()
  const ownerOf = async (c: Context): Promise<string> => {
    const given = givenBearer(c)
    if (!given) {
      const session = store.session(sessionId(c))
      if (!session) throw new AuthRequired('Sign in with ThreatCrush first.')
      if (session.sub) return session.sub
    }
    const bearer = given ?? (await bearerOf(sessionId(c)))
    if (!bearer) throw new AuthRequired('Sign in with ThreatCrush first.')
    const k = keyed(bearer)
    let hit = owners.get(k)
    if (!hit || hit.at < Date.now() - 600_000) {
      if (owners.size > 10_000) owners.clear()
      hit = { sub: await tc.whoami(bearer, tco), at: Date.now() }
      owners.set(k, hit)
    }
    if (!hit.sub) throw new ThreatCrushError('Desktops belong to a person: sign in with ThreatCrush (OAuth) rather than with a tc_agent_ key.', 403, 'needs_person')
    return hit.sub
  }

  /** The c0mpute analyst, rate-limited per address. Null when no node answered (the facts still stand). */
  const analyse = async (c: Context<Env>, work: () => Promise<Analysis | null>): Promise<Analysis | null> => {
    if (!analystEnabled() || !aiLimit.allow(`ai:${ip(c)}`)) return null
    const a = await work()
    store.count(a ? 'analyst_ok' : 'analyst_none')
    return a
  }

  const runCheck = async (c: Context<Env>, q: string, bearer: string | null): Promise<Check> => {
    const limit = bearer ? userLimit : openLimit
    if (!limit.allow(`check:${bearer ? keyed(bearer) : ip(c)}`)) throw new ThreatCrushError('Too many checks. Wait a few minutes.', 429, 'rate_limited')
    const result = await tc.check(q, bearer, tco)
    store.count(result.kind === 'hash' ? 'check_hash' : 'check_reputation')
    return result
  }

  /** Is the desktop's tunnel up and its broker answering? A desktop_status, 2.5 seconds at most. */
  const probe = async (d: Desktop): Promise<{ up: boolean; state?: string; error?: string }> => {
    const token = desktops.token(d.id)
    if (!token) return { up: false }
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      const slow = new Promise<never>((_, no) => (timer = setTimeout(() => no(new DesktopError('The desktop did not answer in time.', 504)), 2500)))
      const r = (await Promise.race([broker(d, token, 'desktop_status', {}), slow])) as { content?: { type?: string; text?: string }[] } | null
      desktops.seen(d.id)
      let state: string | undefined
      try {
        state = (JSON.parse(r?.content?.find((x) => x.type === 'text')?.text ?? '{}') as { state?: string }).state
      } catch {}
      return { up: true, ...(state ? { state } : {}) }
    } catch (e) {
      return { up: false, error: e instanceof Error ? e.message : String(e) }
    } finally {
      clearTimeout(timer)
    }
  }

  app.use('*', async (c, next) => {
    await next()
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) c.header(k, v)
  })

  app.get('/.well-known/openwebring.json', (c) => c.json(ringDescriptor(), 200, { 'access-control-allow-origin': '*' }))
  app.get('/health', (c) => c.json({ ok: true, version: VERSION }))

  // Static files: the stylesheet, the icons, the PWA shell, the Moshpit root.
  const TYPES: Record<string, string> = { css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8', svg: 'image/svg+xml', crt: 'application/x-x509-ca-cert', webmanifest: 'application/manifest+json; charset=utf-8', png: 'image/png' }
  app.get('/:file{(style\\.css|pwa-register\\.js|sw\\.js|manifest\\.webmanifest|icon-192\\.png|icon-512\\.png|icon-maskable-512\\.png|favicon\\.svg|moshpit-root-ca\\.crt)}', async (c) => {
    const name = c.req.param('file')
    const file = Bun.file(new URL(`../public/${name}`, import.meta.url))
    return c.body(await file.arrayBuffer(), 200, { 'content-type': TYPES[name.split('.').pop()!]!, 'cache-control': name === 'sw.js' ? 'no-cache' : 'public, max-age=86400' })
  })

  app.get('/', (c) => page(c, homePage(ctxOf(c))))
  app.get('/connect', (c) => page(c, connectPage(ctxOf(c))))
  app.get('/llms.txt', (c) => c.body(llmsTxt(origin(c)), 200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'public, max-age=3600' }))

  // For crawlers: the public pages, named on the host that was asked.
  const PUBLIC_PATHS = ['/', '/connect']
  app.get('/robots.txt', (c) => c.body(`User-agent: *\nDisallow: /me\nDisallow: /desktops\nDisallow: /auth/\nDisallow: /api/\nDisallow: /check\nDisallow: /go/\nAllow: /\nSitemap: ${origin(c)}/sitemap.xml\n`, 200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'public, max-age=3600' }))
  app.get('/sitemap.xml', (c) =>
    c.body(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${PUBLIC_PATHS.map((p) => `<url><loc>${origin(c)}${p}</loc></url>`).join('')}</urlset>`, 200, { 'content-type': 'application/xml; charset=utf-8', 'cache-control': 'public, max-age=3600' }),
  )

  // The way out to ThreatCrush (and the engines underneath), counted.
  app.get('/go/:dest', (c) => {
    const dest = c.req.param('dest')
    const target = GO[dest]
    if (!target) return c.redirect('/')
    store.count(`go_${dest}`)
    const u = new URL(target)
    u.searchParams.set('utm_source', 'security.agent')
    u.searchParams.set('utm_medium', 'referral')
    u.searchParams.set('utm_campaign', dest)
    return c.redirect(u.toString())
  })

  // Sign in with ThreatCrush.
  app.get('/auth/start', async (c) => {
    // Over plain http there is no callback ThreatCrush will send a code to: sign in through the relay.
    if (direct(c) && !https(c)) return c.redirect(`${RELAY_ORIGIN}/auth/start`)
    if (!authLimit.allow(`auth:${ip(c)}`)) return page(c, messagePage(ctxOf(c), { title: 'Slow down', message: 'Too many sign-in attempts. Try again in a few minutes.' }), 429)
    try {
      const id = await clientId()
      const state = randomBytes(16).toString('base64url')
      const { verifier, challenge } = tc.pkce()
      const redirectUri = `${origin(c)}/auth/callback`
      store.saveState(state, { verifier, redirectUri, clientId: id })
      store.count('signin_start')
      return c.redirect(tc.authorizeUrl({ clientId: id, redirectUri, state, challenge }, tco))
    } catch (e) {
      return page(c, messagePage(ctxOf(c), { title: 'Sign-in is not available', message: e instanceof Error ? e.message : 'ThreatCrush did not answer.' }), 502)
    }
  })

  app.get('/auth/callback', async (c) => {
    const ctx = ctxOf(c)
    const again = { href: '/auth/start', label: 'Sign in with ThreatCrush' }
    if (c.req.query('error')) return page(c, messagePage(ctx, { title: 'Not signed in', message: c.req.query('error_description') ?? 'ThreatCrush did not sign you in.', action: again }), 400)
    const saved = store.takeState(c.req.query('state') ?? '')
    const code = c.req.query('code')
    if (!saved || !code) return page(c, messagePage(ctx, { title: 'Sign-in expired', message: 'That sign-in link is old. Start again.', action: again }), 400)
    // RFC 9207: a code from anyone but ThreatCrush is not ours to redeem.
    const iss = c.req.query('iss')
    if (iss && iss.replace(/\/+$/, '') !== (config.threatcrush ?? tc.THREATCRUSH).replace(/\/+$/, '')) return page(c, messagePage(ctx, { title: 'Not signed in', message: 'That answer did not come from ThreatCrush.', action: again }), 400)
    try {
      const tokens = await tc.exchangeCode({ code, verifier: saved.verifier, clientId: saved.clientId, redirectUri: saved.redirectUri }, tco)
      const sub = await tc.whoami(tokens.accessToken, tco).catch(() => null)
      const sid = store.newSession(tokens, saved.clientId, sub ?? '')
      store.count('signin_done')
      setCookie(c, SESSION, sid, { httpOnly: true, secure: deps.secureCookies ?? https(c), sameSite: 'Lax', path: '/', maxAge: 30 * 86400 })
      return c.redirect('/me')
    } catch (e) {
      return page(c, messagePage(ctx, { title: 'Sign-in failed', message: e instanceof Error ? e.message : 'ThreatCrush did not answer.', action: again }), e instanceof AuthRequired ? 400 : 502)
    }
  })

  app.post('/auth/logout', async (c) => {
    const form = await c.req.parseBody()
    const sid = sessionId(c)
    if (csrfOk(c, form.csrf)) {
      // Signing out ends the grant at ThreatCrush too, not just the cookie.
      const session = store.session(sid)
      if (session) await tc.revoke(session.tokens.refreshToken, tco)
      store.endSession(sid)
    }
    deleteCookie(c, SESSION, { path: '/' })
    return c.redirect('/')
  })

  // The check box. A cross-site POST arrives without the SameSite=Lax cookie, so it can only ever
  // spend the open file-hash lookup, never a signed-in visitor's ThreatCrush allowance.
  const checkFrom = async (c: Context<Env>): Promise<CheckOut> => {
    const form = (await c.req.parseBody()) as Record<string, unknown>
    const q = typeof form.q === 'string' ? form.q.trim().slice(0, 2048) : ''
    if (!q) return { q, error: 'Type an IP address, a domain, a URL or a SHA-256 file hash.', status: 400 }
    try {
      const result = await runCheck(c, q, await bearerOf(sessionId(c)))
      // "Explain" asks the c0mpute analyst too. Public reputation data only.
      if (form.explain === '1') return { q, result, analysis: await analyse(c, () => explainCheck(result, deps.generate)), status: 200 }
      return { q, result, status: 200 }
    } catch (e) {
      if (e instanceof AuthRequired) return { q, error: 'Sign in with ThreatCrush to check an IP address or a domain. File hashes need no account.', needSignIn: true, status: 401 }
      return { q, error: e instanceof Error ? e.message : 'Something went wrong.', status: e instanceof ThreatCrushError ? e.status : 500 }
    }
  }

  app.post('/check', async (c) => {
    const { status, ...form } = await checkFrom(c)
    return page(c, homePage(ctxOf(c), form), status)
  })
  app.get('/check', (c) => c.redirect('/'))

  // The dashboard: the check box, what ThreatCrush has on the visitor's servers, and their desktops.
  const dashboard = async (c: Context<Env>, form?: Omit<CheckOut, 'status'>, status = 200, wantBrief = false) => {
    let bearer: string | null
    try {
      bearer = await bearerOf(sessionId(c))
    } catch {
      bearer = null
    }
    if (!bearer) {
      deleteCookie(c, SESSION, { path: '/' })
      return c.redirect('/auth/start')
    }
    const soft = (e: unknown) => (e instanceof Error ? e.message : 'ThreatCrush did not answer.')
    const [f, i] = await Promise.allSettled([tc.findings(bearer, {}, tco), tc.incidents(bearer, { status: 'open,acknowledged' }, tco)])
    // The brief sends this organization's own findings and incidents (secrets stripped) to c0mpute
    // peer nodes, so it runs only when the person presses the button that says so.
    const briefing = wantBrief ? await analyse(c, () => brief({ findings: f.status === 'fulfilled' ? f.value : [], incidents: i.status === 'fulfilled' ? i.value : [] }, deps.generate)) : undefined
    const sub = store.session(sessionId(c))?.sub
    return page(
      c,
      dashboardPage(ctxOf(c), {
        findings: f.status === 'fulfilled' ? f.value : null,
        ...(f.status === 'rejected' ? { findingsError: soft(f.reason) } : {}),
        incidents: i.status === 'fulfilled' ? i.value : null,
        ...(i.status === 'rejected' ? { incidentsError: soft(i.reason) } : {}),
        ...(form ? { form } : {}),
        ...(briefing !== undefined ? { brief: briefing } : {}),
        desktops: sub ? desktops.list(sub).length : 0,
      }),
      status,
    )
  }
  app.get('/me', (c) => dashboard(c))
  app.post('/me', async (c) => {
    if (!signedIn(c)) return c.redirect('/auth/start')
    const { status, ...form } = await checkFrom(c)
    return dashboard(c, form, status)
  })
  app.post('/me/brief', async (c) => {
    if (!signedIn(c)) return c.redirect('/auth/start')
    const form = await c.req.parseBody()
    if (!csrfOk(c, form.csrf)) return c.redirect('/me', 303)
    return dashboard(c, undefined, 200, true)
  })

  // Desktops: the person's own computers, reached through the tunnel each one opens.
  const desktopsView = async (c: Context<Env>, extra: { error?: string; added?: Desktop } = {}, status = 200) => {
    let owner: string
    try {
      owner = await ownerOf(c)
    } catch (e) {
      if (e instanceof AuthRequired) return c.redirect('/auth/start')
      return page(c, messagePage(ctxOf(c), { title: 'Desktops need a person', message: e instanceof Error ? e.message : String(e) }), 403)
    }
    const list = desktops.list(owner)
    const live = await Promise.all(list.map((d) => probe(d)))
    return page(c, desktopsPage(ctxOf(c), { desktops: list.map((d, n) => ({ ...d, live: live[n]! })), tunnelHost, setup: (d) => setupScript(d, tunnelHost, tunnelUser), ...extra }), status)
  }
  app.get('/desktops', (c) => desktopsView(c))
  app.post('/desktops', async (c) => {
    const form = (await c.req.parseBody()) as Record<string, unknown>
    if (!csrfOk(c, form.csrf)) return desktopsView(c, { error: 'That form went stale. Try again.' }, 400)
    try {
      const added = desktops.add(await ownerOf(c), { name: form.name, publicKey: form.public_key, token: form.token, brokerPort: form.broker_port })
      store.count('desktop_added')
      return desktopsView(c, { added })
    } catch (e) {
      return desktopsView(c, { error: e instanceof Error ? e.message : String(e) }, e instanceof DesktopError ? e.status : 400)
    }
  })
  app.post('/desktops/:id/delete', async (c) => {
    const form = await c.req.parseBody()
    if (csrfOk(c, form.csrf)) desktops.remove(await ownerOf(c).catch(() => ''), c.req.param('id'))
    return c.redirect('/desktops', 303)
  })

  // The JSON API.
  const apiError = (c: Context, e: unknown) => {
    if (e instanceof AuthRequired) {
      return c.json({ error: e.message, code: e.code, sign_in: `${origin(c)}/auth/start`, mcp: tc.mcpUrl(tco) }, 401, { 'www-authenticate': 'Bearer realm="security.agent", error="invalid_token"' })
    }
    if (e instanceof ThreatCrushError || e instanceof DesktopError) return c.json({ error: e.message, code: e instanceof ThreatCrushError ? e.code : 'desktop' }, e.status as 400)
    console.error(e instanceof Error ? e.message : e)
    return c.json({ error: 'Something went wrong.' }, 500)
  }

  const truthy = (v: unknown) => v === true || v === '1' || v === 'true'
  const apiCheck = async (c: Context<Env>, q: unknown, explain: boolean) => {
    try {
      if (typeof q !== 'string' || !q.trim()) return c.json({ error: 'q is required: an IP address, a domain, a URL or a SHA-256 file hash', code: 'bad_indicator' }, 400)
      const result = await runCheck(c, q.trim().slice(0, 2048), await credential(c))
      if (!explain) return c.json(result, 200, { 'cache-control': 'no-store' })
      return c.json({ ...result, analysis: await analyse(c, () => explainCheck(result, deps.generate)) }, 200, { 'cache-control': 'no-store' })
    } catch (e) {
      return apiError(c, e)
    }
  }
  app.get('/api/v1/check', (c) => apiCheck(c, c.req.query('q'), truthy(c.req.query('explain'))))
  app.post('/api/v1/check', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as { q?: unknown; explain?: unknown }
    return apiCheck(c, body.q, truthy(body.explain))
  })

  const needBearer = async (c: Context) => {
    const bearer = await credential(c)
    if (!bearer) throw new AuthRequired('Send a ThreatCrush credential as the Bearer token, or sign in.')
    return bearer
  }

  app.get('/api/v1/findings', async (c) => {
    try {
      const bearer = await needBearer(c)
      const { status, severity } = c.req.query()
      return c.json({ findings: await tc.findings(bearer, { ...(status ? { status } : {}), ...(severity ? { severity } : {}), limit: Math.min(Number(c.req.query('limit')) || 25, 500) }, tco) }, 200, { 'cache-control': 'no-store' })
    } catch (e) {
      return apiError(c, e)
    }
  })

  app.get('/api/v1/incidents', async (c) => {
    try {
      const bearer = await needBearer(c)
      const { status, host } = c.req.query()
      return c.json({ incidents: await tc.incidents(bearer, { ...(status ? { status } : {}), ...(host ? { host } : {}), limit: Math.min(Number(c.req.query('limit')) || 25, 500) }, tco) }, 200, { 'cache-control': 'no-store' })
    } catch (e) {
      return apiError(c, e)
    }
  })

  // A brief on the caller's open incidents and findings, written on c0mpute. The caller asked for it,
  // so their own data goes to c0mpute peer nodes (secrets stripped first).
  app.post('/api/v1/brief', async (c) => {
    try {
      const bearer = await needBearer(c)
      const [findings, incidents] = await Promise.all([tc.findings(bearer, {}, tco), tc.incidents(bearer, { status: 'open,acknowledged' }, tco)])
      const analysis = await analyse(c, () => brief({ findings, incidents }, deps.generate))
      return c.json({ analysis, incidents: incidents.length, findings: findings.length, note: 'Written by an open model on the c0mpute peer network from your ThreatCrush data. null means no node answered.' }, 200, { 'cache-control': 'no-store' })
    } catch (e) {
      return apiError(c, e)
    }
  })

  // Desktops over the API: list with live status, and one desktop tool call through the tunnel.
  app.get('/api/v1/desktops', async (c) => {
    try {
      const list = desktops.list(await ownerOf(c))
      const live = await Promise.all(list.map((d) => probe(d)))
      return c.json(
        { desktops: list.map((d, n) => ({ id: d.id, name: d.name, port: d.port, connected: live[n]!.up, state: live[n]!.state ?? null, error: live[n]!.up ? null : (live[n]!.error ?? null), seen_at: d.seenAt ? new Date(d.seenAt).toISOString() : null })), tools: DESKTOP_TOOLS },
        200,
        { 'cache-control': 'no-store' },
      )
    } catch (e) {
      return apiError(c, e)
    }
  })
  app.post('/api/v1/desktops/:id/call', async (c) => {
    try {
      const d = desktops.get(await ownerOf(c), c.req.param('id'))
      if (!d) return c.json({ error: 'no such desktop' }, 404)
      const body = (await c.req.json().catch(() => ({}))) as { tool?: unknown; arguments?: unknown }
      const tool = String(body.tool ?? '')
      if (!(DESKTOP_TOOLS as readonly string[]).includes(tool)) return c.json({ error: `tool must be one of: ${DESKTOP_TOOLS.join(', ')}`, code: 'bad_tool' }, 400)
      const args = body.arguments && typeof body.arguments === 'object' && !Array.isArray(body.arguments) ? (body.arguments as Record<string, unknown>) : {}
      if (!desktopLimit.allow(`desk:${d.id}`)) return c.json({ error: 'Too many desktop calls. Slow down.', code: 'rate_limited' }, 429)
      const result = await broker(d, desktops.token(d.id)!, tool, args)
      desktops.seen(d.id)
      store.count('desktop_call')
      return c.json({ result }, 200, { 'cache-control': 'no-store' })
    } catch (e) {
      return apiError(c, e)
    }
  })

  // ThreatCrush's own tool list, kept for an hour.
  let tools: { at: number; list: ToolDef[] } | null = null
  app.get('/api/v1/tools', async (c) => {
    try {
      if (!tools || tools.at < Date.now() - 3_600_000) tools = { at: Date.now(), list: await tc.listTools(tco) }
      return c.json({ mcp: tc.mcpUrl(tco), tools: tools.list.map((t) => ({ name: t.name, description: t.description })), desktop_tools: DESKTOP_TOOLS }, 200, { 'cache-control': 'public, max-age=3600' })
    } catch (e) {
      return apiError(c, e)
    }
  })

  // The funnel, in totals per day. Operators only.
  app.get('/api/v1/stats', (c) => {
    const given = Buffer.from(givenBearer(c) ?? '')
    const expected = Buffer.from(config.adminKey ?? '')
    if (expected.length < 16 || given.length !== expected.length || !timingSafeEqual(given, expected)) return c.json({ error: 'not found' }, 404)
    return c.json({ stats: store.stats(Math.min(Number(c.req.query('days')) || 30, 365)) })
  })

  app.notFound((c) => (c.req.path.startsWith('/api/') ? c.json({ error: 'not found' }, 404) : page(c, messagePage(ctxOf(c), { title: 'Not found', message: 'That page does not exist.' }), 404)))
  app.onError((error, c) => {
    console.error(error instanceof Error ? error.message : error)
    return c.req.path.startsWith('/api/') ? c.json({ error: 'Something went wrong.' }, 500) : page(c, messagePage(ctxOf(c), { title: 'Something went wrong', message: 'Try again in a moment.' }), 500)
  })
  return Object.assign(app, { desktops })
}

export function serve(options: { port?: number; hostname?: string } = {}) {
  const env = process.env
  const key = env.SECAGENT_KEY ?? ''
  const store = new Store(env.SECAGENT_DB ?? `${env.HOME}/.local/share/security-agent/security-agent.db`, new Sealer(key))
  const config: Config = {
    ...(env.SECAGENT_THREATCRUSH_URL ? { threatcrush: env.SECAGENT_THREATCRUSH_URL } : {}),
    ...(env.SECAGENT_TC_CLIENT_ID ? { clientId: env.SECAGENT_TC_CLIENT_ID } : {}),
    ...(env.SECAGENT_ADMIN_KEY ? { adminKey: env.SECAGENT_ADMIN_KEY } : {}),
    ...(env.SECAGENT_TUNNEL_HOST ? { tunnelHost: env.SECAGENT_TUNNEL_HOST } : {}),
    ...(env.SECAGENT_TUNNEL_USER ? { tunnelUser: env.SECAGENT_TUNNEL_USER } : {}),
    ...(env.SECAGENT_TUNNEL_KEYS ? { tunnelKeysFile: env.SECAGENT_TUNNEL_KEYS } : {}),
  }
  const app = createApp({ store, key, config })
  // sshd reads the desktops' keys from this file: write it at start, so a restored database is honoured.
  app.desktops.writeKeys()
  const trustProxy = (env.SECAGENT_TRUST_PROXY ?? '1') === '1'
  startRingRefresh()
  startRingFooterRefresh()
  startPitFooterRefresh(SELF)
  return Bun.serve({
    port: options.port ?? Number(env.PORT ?? 8799),
    hostname: options.hostname ?? env.HOST ?? '127.0.0.1',
    idleTimeout: 120,
    fetch(request, srv) {
      const peer = srv.requestIP(request)?.address ?? ''
      const forwarded = trustProxy && (peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1') ? request.headers.get('x-real-ip') : null
      return app.fetch(request, { ip: forwarded || peer })
    },
  })
}

if (import.meta.main) {
  const server = serve()
  console.log(`security.agent listening on http://${server.hostname}:${server.port}`)
}

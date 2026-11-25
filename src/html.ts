/**
 * Server-rendered pages. No page needs script: the check box is a plain form.
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { pitFooter } from './pit-footer.js'
import { ringFooter } from './ring-footer.js'
import { RING_PLACEHOLDER } from './ring.js'
import type { Analysis } from './analyst.js'
import type { Desktop } from './desktops.js'
import type { Check, Finding, Incident } from './threatcrush.js'

export const SITE = 'https://security.agent'
export const REPO = 'https://github.com/moshcoder/security.agent'
export const NPM = '@profullstack/securityagent'
export const TC_MCP = 'https://threatcrush.com/api/mcp'

/** crawlproof analytics: one async script on every page, when a site id is configured. */
const TRACKER_SITE = process.env.CRAWLPROOF_SITE ?? ''
const TRACKER = /^[0-9a-f-]{36}$/.test(TRACKER_SITE) ? `<script data-site="${TRACKER_SITE}" src="https://crawlproof.com/stats.js" async></script>` : ''
// WebMCP (@profullstack/webmcp): site_info, open_page and the check form as tools for the AI agent in the visitor's browser.
const WEBMCP = `<script type="module" data-webmcp src="https://cdn.jsdelivr.net/npm/@profullstack/webmcp@0/src/embed.js" data-pages='{"home":"/","connect":"/connect","dashboard":"/me"}'></script>`

/**
 * A crawlproof ad: a cross-origin, sandboxed iframe, so it can never read the
 * page. One text link at the top of the content of an inner public page: never
 * on the home page, never by a footer, never where someone signs in or types.
 * Off until CRAWLPROOF_AD_SLOT names a slot.
 */
export const AD_SLOT = process.env.CRAWLPROOF_AD_SLOT ?? 'off'
export const adUnit = () =>
  AD_SLOT === 'off' ? '' : `<div class="ad-unit"><iframe src="https://crawlproof.com/api/ads/frame?slot=${encodeURIComponent(AD_SLOT)}&amp;format=text_link" title="Advertisement" loading="lazy" referrerpolicy="strict-origin-when-cross-origin" sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation" scrolling="no"></iframe></div>`

const asset = (name: string) => {
  const body = readFileSync(new URL(`../public/${name}`, import.meta.url))
  return `/${name}?v=${createHash('sha256').update(body).digest('hex').slice(0, 10)}`
}
const STYLE_URL = asset('style.css')

const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }
export const esc = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, (c) => ESC[c]!)

const LOGO = `<svg class="mark" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 4l10 4v7c0 6.2-4.1 10.6-10 13C10.100 25.600 6 21.200 6 15V8z" fill="none" stroke="currentColor" stroke-width="2.800" stroke-linejoin="round"/><path d="M11.500 15.800l3.200 3.200 5.800-6.200" fill="none" stroke="currentColor" stroke-width="2.800" stroke-linecap="round" stroke-linejoin="round"/></svg>`

export type Ctx = { signedIn: boolean; origin: string; csrf: string }

type LayoutOptions = { title: string; description: string; path: string; body: string; ctx: Ctx; noindex?: boolean; ads?: boolean }

function layout(o: LayoutOptions): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(o.title)}</title>
<meta name="description" content="${esc(o.description)}">
<meta name="referrer" content="strict-origin-when-cross-origin">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#07090c">
<link rel="manifest" href="/manifest.webmanifest">
${o.noindex ? '<meta name="robots" content="noindex">' : `<link rel="canonical" href="${esc(SITE + o.path)}">`}
<meta property="og:type" content="website">
<meta property="og:site_name" content="security.agent">
<meta property="og:title" content="${esc(o.title)}">
<meta property="og:description" content="${esc(o.description)}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="${STYLE_URL}">
<script src="/pwa-register.js" defer></script>
${TRACKER}
${WEBMCP}
</head>
<body>
${RING_PLACEHOLDER}
<header class="top">
  <a class="brand" href="/">${LOGO}<span>security<b>.</b>agent</span></a>
  <nav aria-label="Site">
    <a href="/connect">Connect an agent</a>
    <a href="/go/threatcrush">ThreatCrush</a>
    ${o.ctx.signedIn ? `<a href="/me">Dashboard</a><a href="/desktops">Desktops</a><form method="post" action="/auth/logout"><input type="hidden" name="csrf" value="${esc(o.ctx.csrf)}"><button class="linkish">Sign out</button></form>` : '<a href="/auth/start">Sign in</a>'}
  </nav>
</header>
<main>
${o.ads ? adUnit() : ''}
${o.body}
</main>
${ringFooter()}
${pitFooter()}
</body>
</html>`
}

const VERDICT: Record<Check['verdict'], { label: string; cls: string }> = {
  malicious: { label: 'Malicious', cls: 'bad' },
  suspicious: { label: 'Reported', cls: 'warn' },
  clean: { label: 'Not listed', cls: 'ok' },
  unknown: { label: 'Unknown', cls: 'unknown' },
}

const SHOWN = ['severity', 'reports', 'reporters', 'country', 'city', 'asn', 'network', 'firstSeen', 'lastSeen', 'first_seen', 'last_seen', 'malwareName', 'fileName', 'trust', 'knownMalicious']

/** One check's answer: the verdict, one sentence, the facts ThreatCrush gave, and the next step. */
export function checkCard(r: Check): string {
  const v = VERDICT[r.verdict]
  const facts = SHOWN.filter((k) => ['string', 'number'].includes(typeof r.details[k]) && r.details[k] !== '')
    .map((k) => `<tr><th>${esc(k.replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase())}</th><td>${esc(r.details[k])}</td></tr>`)
    .join('')
  const rules = Array.isArray(r.details.rules) ? r.details.rules.slice(0, 8).map((x) => `<code>${esc(typeof x === 'string' ? x : ((x as { rule?: string; name?: string })?.rule ?? (x as { name?: string })?.name ?? JSON.stringify(x)))}</code>`).join(' ') : ''
  const next =
    r.kind === 'hash'
      ? '<a href="/go/antivirus">Scan whole files free with CrushAV</a>, nothing uploaded.'
      : r.verdict === 'clean'
        ? 'Not listed means no ThreatCrush server reported it, not that it is safe. <a href="/go/install">Run ThreatCrush on your own servers</a> to see and block what reaches you.'
        : '<a href="/go/install">Run ThreatCrush on your servers</a> and it bans addresses like this one by itself.'
  return `<section class="card result" aria-live="polite">
  <p class="verdict ${v.cls}"><span>${v.label}</span><code>${esc(r.indicator)}</code></p>
  <p>${esc(r.summary)}</p>
  ${facts ? `<table>${facts}</table>` : ''}
  ${rules ? `<p class="small muted">Rules that fired: ${rules}</p>` : ''}
  <p class="small muted">${next}</p>
</section>`
}

/** What the c0mpute analyst wrote, or why there is nothing (the facts above it still stand). */
export function analysisCard(a: Analysis | null, what = 'analysis'): string {
  if (!a) return `<section class="card analysis"><p class="muted small">No c0mpute node answered in time, so there is no ${what} this time. The ThreatCrush facts above are complete. Try again in a minute.</p></section>`
  return `<section class="card analysis">
  <h3>Analyst <span class="muted small">on <a href="/go/c0mpute">c0mpute</a>${a.model ? `, ${esc(a.model)}` : ''}</span></h3>
  ${a.text.split(/\n{2,}/).map((p) => `<p>${esc(p).replace(/\n/g, '<br>')}</p>`).join('')}
  <p class="muted small">Written by an open model on the c0mpute peer network from the facts ThreatCrush gave. It can be wrong; the facts are not.</p>
</section>`
}

type CheckForm = { q?: string; result?: Check; analysis?: Analysis | null; error?: string; needSignIn?: boolean }

function checkForm(ctx: Ctx, f: CheckForm, action = '/check'): string {
  return `<form class="check" method="post" action="${action}" toolname="check_indicator" tooldescription="Check an IP address, a domain, a URL or a SHA-256 file hash against ThreatCrush. File hashes need no sign-in." toolautosubmit>
  <label class="sr" for="q">IP address, domain, URL or SHA-256 file hash</label>
  <div class="row">
    <input id="q" name="q" value="${esc(f.q ?? '')}" placeholder="IP, domain, URL or SHA-256 file hash" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="2048" required>
    <button class="btn">Check</button>
    <button class="btn ghost" name="explain" value="1" title="Check, then have the c0mpute analyst explain what it means">Check + explain</button>
  </div>
</form>
${f.error ? `<p class="error" role="alert">${esc(f.error)}${f.needSignIn ? ` <a class="btn small-btn" href="/auth/start?q=${encodeURIComponent(f.q ?? '')}">Sign in with ThreatCrush</a>` : ''}</p>` : ''}
${f.result ? checkCard(f.result) : ''}
${f.result && f.analysis !== undefined ? analysisCard(f.analysis, 'explanation') : ''}
${ctx.signedIn ? '' : '<p class="muted small center">File hashes are free with no account. IP addresses and domains need a free ThreatCrush sign-in.</p>'}`
}

const CONNECT = `<div class="card">
  <h3>Claude Code, Codex and other terminals</h3>
  <pre><code>claude mcp add --transport http threatcrush ${TC_MCP}</code></pre>
  <p class="muted small">The first tool call opens a browser to sign in with ThreatCrush (OAuth 2.1 with PKCE). Nothing to paste.</p>
  <h3>claude.ai, ChatGPT and other connector screens</h3>
  <pre><code>${TC_MCP}?login</code></pre>
  <p class="muted small">Add it as a custom connector. The <code>?login</code> form asks for sign-in right away, for screens that only offer OAuth when the first request is refused.</p>
  <h3>From a shell or a script</h3>
  <pre><code>bunx ${NPM} login          # OAuth 2.1 in your browser
bunx ${NPM} check 203.0.113.9
bunx ${NPM} findings</code></pre>
  <p class="muted small">Or a local MCP server on stdio: <code>claude mcp add securityagent -- bunx ${NPM} mcp</code>. On a server with no browser, set <code>THREATCRUSH_API_KEY</code> to a <code>tc_agent_</code> key instead of signing in.</p>
</div>`

/** The two-way tunnel, drawn: one outbound SSH connection from the desktop carries both directions. */
const TUNNEL_DIAGRAM = `<svg class="diagram" viewBox="0 0 640 170" role="img" aria-label="Your desktop opens one outbound SSH connection to the security.agent server. The server's calls travel back down the same connection to the W3BS desktop broker on the desktop.">
  <rect x="8" y="30" width="190" height="110" rx="10" class="d-box"/>
  <text x="103" y="58" class="d-title">Your desktop</text>
  <text x="103" y="82" class="d-text">W3BS desktop broker</text>
  <text x="103" y="100" class="d-mono">127.0.0.1:7801</text>
  <text x="103" y="124" class="d-small">you approve, you can stop it</text>
  <rect x="442" y="30" width="190" height="110" rx="10" class="d-box"/>
  <text x="537" y="58" class="d-title">security.agent</text>
  <text x="537" y="82" class="d-text">server (dev2)</text>
  <text x="537" y="100" class="d-mono">127.0.0.1:&lt;your port&gt;</text>
  <text x="537" y="124" class="d-small">your agent's calls start here</text>
  <path d="M206 66 H434" class="d-line"/><path d="M426 60 L436 66 L426 72" class="d-line"/>
  <text x="320" y="56" class="d-small">1. desktop dials out: ssh -R (no open port at home)</text>
  <path d="M434 106 H206" class="d-line d-accent"/><path d="M214 100 L204 106 L214 112" class="d-line d-accent"/>
  <text x="320" y="128" class="d-small">2. agent's MCP calls ride back down the same connection</text>
</svg>`

const UNDER_THE_HOOD = `<section id="under-the-hood">
  <h2>Under the hood</h2>
  <div class="grid3">
    <div class="card"><h3><a href="/go/threatcrush">ThreatCrush</a></h3><p class="muted small">The facts: what independent servers blocked, which files are malware, what was found and raised on your servers. Every answer starts here.</p></div>
    <div class="card"><h3><a href="/go/c0mpute">c0mpute</a></h3><p class="muted small">The analyst. Open models on a peer-to-peer network explain a result and say what to fix first. No paid AI, and nothing is made up when no node answers.</p></div>
    <div class="card"><h3><a href="/go/w3bs">W3BS desktop</a></h3><p class="muted small">Your own computer, for work that has to happen there: a browser to look at, an app to click through, a 2FA prompt handed to you.</p></div>
  </div>
  <h3>Your desktop, both ways, one connection</h3>
  <p>Once signed in you can add a desktop. It runs the <a href="/go/w3bs">W3BS Agentic Desktop Layer</a> and opens a single outbound SSH connection to us. That connection carries traffic both ways: the desktop reaches the server, and your agent's calls come back down the same connection to the desktop's broker. Your home needs no open port and no VPN.</p>
  ${TUNNEL_DIAGRAM}
  <p class="muted small">We run the same setup ourselves: our server dev2 reaches our desktop bonita through a tunnel bonita opens. The desktop's key can do exactly one thing on our server: listen on its own loopback port. The broker asks you before an agent drives, shows what it does, and stops on Super+Alt+Escape. Turning off one service on the desktop cuts the connection.</p>
</section>`

export function homePage(ctx: Ctx, f: CheckForm = {}): string {
  return layout({
    ctx,
    title: 'security.agent: a security team for your AI agent',
    description: 'Give any AI agent ThreatCrush: check IPs, domains and files, read your findings and incidents. Sign in with ThreatCrush over OAuth 2.1, or use the CLI and MCP.',
    path: '/',
    body: `<section class="hero">
  <h1>A security team<br>for your AI agent.</h1>
  <p class="tag">Your agent reads links, runs code and talks to strangers. Give it somewhere to ask: is this address attacking people, is this domain on a blocklist, is this file malware, what is open on my servers. Answers come from <a href="/go/threatcrush">ThreatCrush</a>.</p>
</section>
${checkForm(ctx, f)}
<div class="grid3">
  <div class="card"><h2><span class="step-n">1</span>Sign in</h2><p class="muted">With ThreatCrush, over OAuth 2.1. We never see your password, and you can cut us off from your ThreatCrush account at any time.</p></div>
  <div class="card"><h2><span class="step-n">2</span>Connect</h2><p class="muted">One line adds the ThreatCrush tools to Claude, ChatGPT, Codex or your own agent. Or use the CLI.</p></div>
  <div class="card"><h2><span class="step-n">3</span>Ask</h2><p class="muted">"Is 203.0.113.9 safe to call?" "Anything critical open on my servers?" "Mark that finding fixed."</p></div>
</div>
<p class="center"><a class="btn big" href="${ctx.signedIn ? '/me' : '/auth/start'}">${ctx.signedIn ? 'Open my dashboard' : 'Sign in with ThreatCrush'}</a></p>
<p class="muted small center">No ThreatCrush account? You make one on the way. Free.</p>
<section id="connect">
  <h2>Connect your agent</h2>
  ${CONNECT}
  <p class="small"><a href="/connect">Every tool, the API and the CLI</a></p>
</section>
${UNDER_THE_HOOD}
<section id="threatcrush">
  <h2>Looking things up is the small part</h2>
  <p>security.agent answers questions. <a href="/go/threatcrush">ThreatCrush</a> does the work: an open-source agent on your Linux servers that watches nginx, SSH and inbound connections, bans attackers at the firewall by itself, scans your code, pentests your URLs and red-teams your LLM apps. What it finds becomes the findings and incidents your AI agent reads here.</p>
  <pre><code>curl -fsSL https://threatcrush.com/install.sh | sh</code></pre>
  <p class="muted small">Free and open source (MIT). Paid extras are optional: Reputation Pro for history and network context, Link Watch, and a human-reviewed scan. <a href="/go/pricing">Pricing</a></p>
  <p><a class="btn ghost" href="/go/install">Install ThreatCrush</a></p>
</section>`,
  })
}

const TOOLS: [string, string, string][] = [
  ['av_hash_lookup', 'no sign-in', 'Is this file known malware, or a published known-good file? Up to 100 SHA-256 hashes; file contents never leave the machine.'],
  ['reputation_lookup', 'read', 'Did independent ThreatCrush servers block this IP address or domain? Listed or not, a 0 to 100 score, reports, rules, country.'],
  ['reputation_bulk', 'read', 'The same for up to 100 indicators at once (1,000 with Reputation Pro).'],
  ['findings_list, findings_get', 'read', 'What threatcrush scan, pentest and ai-scan found in your code, URLs and LLM apps, deduped across runs.'],
  ['findings_triage', 'write', 'Acknowledge a finding, mark it fixed, a false positive or ignored, with a note.'],
  ['incidents_list, incidents_get', 'read', 'Incidents raised to your team: evidence, the source address, block history, fix progress.'],
  ['incidents_update', 'write', 'Record fix work: assignees, PR link, test status, resolution.'],
  ['incidents_raise', 'write, pages people', 'Raise an incident. A new one pages the team by SMS and email, so an agent should ask first.'],
  ['webhooks_*', 'read and write', 'Signed webhooks for detection.created, findings.raised and reputation.changed.'],
]

export function connectPage(ctx: Ctx): string {
  const o = esc(ctx.origin)
  return layout({
    ctx,
    ads: true,
    title: 'Connect an AI agent to ThreatCrush: MCP, CLI and API | security.agent',
    description: 'Add ThreatCrush security tools to Claude, ChatGPT, Codex or your own agent: the MCP URL, OAuth 2.1 sign-in, the securityagent CLI and the JSON API.',
    path: '/connect',
    body: `<h1>Connect an agent</h1>
<p class="tag">ThreatCrush runs an MCP server with OAuth 2.1. Point an agent at it, sign in once, and the agent can check addresses and files, read what was found on your servers, and record the fix.</p>
<section id="mcp">
  <h2>MCP</h2>
  ${CONNECT}
</section>
<section id="tools">
  <h2>What the agent gets</h2>
  <table class="tools"><thead><tr><th>Tool</th><th>Needs</th><th>What it answers</th></tr></thead><tbody>
  ${TOOLS.map(([name, needs, what]) => `<tr><td><code>${esc(name)}</code></td><td class="muted small">${esc(needs)}</td><td>${esc(what)}</td></tr>`).join('\n  ')}
  </tbody></table>
  <p class="muted small">Read tools are safe to call freely. The write tools change what your team sees, so tell your agent to confirm with you first. The live list: <a href="/api/v1/tools">/api/v1/tools</a>.</p>
</section>
<section id="oauth">
  <h2>Sign-in, exactly</h2>
  <p>ThreatCrush is the authorization server. Clients are public (no secret), register themselves (RFC 7591), and use the authorization code grant with PKCE S256. Access tokens last an hour and refresh tokens rotate. A token works on the MCP endpoint and nowhere else.</p>
  <pre><code>Discovery      https://threatcrush.com/.well-known/oauth-authorization-server
Resource       https://threatcrush.com/.well-known/oauth-protected-resource
Scope          mcp</code></pre>
  <p class="muted small">See and revoke what you approved in your <a href="/go/threatcrush">ThreatCrush</a> account. Signing out here revokes this site's grant.</p>
</section>
<section id="cli">
  <h2>CLI and TUI</h2>
  <pre><code>bunx ${NPM}                     # interactive
bunx ${NPM} login               # sign in with ThreatCrush (OAuth 2.1, loopback redirect)
bunx ${NPM} check example.com   # an IP, a domain, a URL or a SHA-256
bunx ${NPM} check --file ./download.bin   # hashes the file locally, sends only the hash
bunx ${NPM} findings --severity critical,high
bunx ${NPM} incidents --status open
bunx ${NPM} mcp                 # MCP server on stdio
bunx ${NPM} logout              # revoke and forget the token</code></pre>
  <p class="muted small">The CLI talks to ThreatCrush directly: your token stays in <code>~/.config/securityagent</code> on your machine and never passes through this site. <code>--json</code> on any command. Exit code 2 means malicious, so a script can gate on it.</p>
</section>
<section id="engines">
  <h2>Which engine answers what</h2>
  <table class="tools"><thead><tr><th>Ask</th><th>Goes to</th></tr></thead><tbody>
  <tr><td>Is this address, domain or file bad? What was found or raised on my servers?</td><td><a href="/go/threatcrush">ThreatCrush</a>: facts, always first</td></tr>
  <tr><td>What does this result mean? What should I fix first?</td><td><a href="/go/c0mpute">c0mpute</a>: open models on peer nodes, only when asked (<code>explain=1</code>, <code>/api/v1/brief</code>)</td></tr>
  <tr><td>Do something on my own computer: open a page, click through an app, hand me a 2FA prompt</td><td><a href="/go/w3bs">W3BS desktop</a>: through the tunnel your desktop opens, with your approval</td></tr>
  </tbody></table>
</section>
<section id="api">
  <h2>API</h2>
  <p>For a script that already holds a ThreatCrush credential (an OAuth access token or a <code>tc_agent_</code> key). It is passed through to ThreatCrush for that one request and not stored.</p>
  <pre><code>curl ${o}/api/v1/check?q=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
curl -H "Authorization: Bearer $THREATCRUSH_API_KEY" "${o}/api/v1/check?q=203.0.113.9"
curl -H "Authorization: Bearer $THREATCRUSH_API_KEY" ${o}/api/v1/findings
curl -H "Authorization: Bearer $THREATCRUSH_API_KEY" ${o}/api/v1/incidents

# the c0mpute analyst
curl "${o}/api/v1/check?q=203.0.113.9&amp;explain=1" -H "Authorization: Bearer $TOKEN"
curl -X POST ${o}/api/v1/brief -H "Authorization: Bearer $TOKEN"

# your desktops (needs a person's OAuth token, not a tc_agent_ key)
curl ${o}/api/v1/desktops -H "Authorization: Bearer $TOKEN"
curl -X POST ${o}/api/v1/desktops/dt_…/call -H "Authorization: Bearer $TOKEN" \\
     -H 'content-type: application/json' -d '{"tool":"desktop_screenshot","arguments":{}}'</code></pre>
  <p class="muted small">A desktop call goes through the tunnel to the W3BS broker on that desktop, which applies its own grants and asks the person before an agent drives. Tools: <code>desktop_status</code>, <code>desktop_windows</code>, <code>desktop_screenshot</code>, <code>task_begin</code>, <code>mouse_click</code>, <code>keyboard_type</code>, <code>human_step</code> and the rest of the <a href="/go/w3bs">desktop layer</a>.</p>
  <p class="muted small">Agents reading this site: <a href="/llms.txt">/llms.txt</a>. Source: <a href="${REPO}">${REPO.replace('https://', '')}</a> (MIT).</p>
</section>
<section>
  <h2>Then protect the servers</h2>
  <p>An agent that can read incidents is most useful when something is producing them. <a href="/go/install">Install ThreatCrush</a> on a Linux server and it starts detecting and banning in a minute.</p>
  <pre><code>curl -fsSL https://threatcrush.com/install.sh | sh</code></pre>
</section>`,
  })
}

const sev = (s: unknown) => `<span class="sev sev-${esc(String(s ?? 'info').toLowerCase().replace(/[^a-z]/g, ''))}">${esc(s ?? 'info')}</span>`

export type Dashboard = { findings: Finding[] | null; findingsError?: string; incidents: Incident[] | null; incidentsError?: string; form?: CheckForm; brief?: Analysis | null; desktops?: number }

export function dashboardPage(ctx: Ctx, d: Dashboard): string {
  const empty = (what: string, error: string | undefined) =>
    error
      ? `<p class="muted">${esc(error)}</p><p class="small"><a href="/go/install">Install ThreatCrush on a server</a> and link it to your account to start seeing ${what} here.</p>`
      : `<p class="muted">No open ${what}.</p><p class="small muted">${what === 'findings' ? 'Run <code>threatcrush scan</code>, <code>pentest</code> or <code>ai-scan</code> while signed in and what they find lands here.' : 'The ThreatCrush daemon raises one when it sees something critical on a linked server.'} <a href="/go/install">Install ThreatCrush</a></p>`
  const findingRows = (d.findings ?? [])
    .map((f) => `<tr><td>${sev(f.severity)}</td><td>${esc(f.message ?? f.title ?? f.type ?? f.id)}${f.location ? `<br><span class="muted small mono">${esc(typeof f.location === 'string' ? f.location : JSON.stringify(f.location))}</span>` : ''}</td><td class="muted small">${esc(f.source ?? '')}</td><td class="muted small">${esc(f.status ?? '')}</td></tr>`)
    .join('')
  const incidentRows = (d.incidents ?? [])
    .map((i) => `<tr><td>${sev(i.severity)}</td><td>${esc(i.title ?? i.summary ?? i.id)}</td><td class="muted small">${esc(i.host ?? '')}</td><td class="muted small">${esc(i.status ?? '')}</td></tr>`)
    .join('')
  return layout({
    ctx,
    noindex: true,
    title: 'Dashboard | security.agent',
    description: 'Check an address or a file, and see your ThreatCrush findings and incidents.',
    path: '/me',
    body: `<h1>Dashboard</h1>
<p class="muted">Signed in with ThreatCrush. Lookups here count against your ThreatCrush daily allowance.</p>
${checkForm(ctx, d.form ?? {}, '/me')}
<section>
  <h2>Open incidents</h2>
  ${incidentRows ? `<table><thead><tr><th>Severity</th><th>Incident</th><th>Host</th><th>Status</th></tr></thead><tbody>${incidentRows}</tbody></table>` : empty('incidents', d.incidentsError)}
</section>
<section>
  <h2>Open findings</h2>
  ${findingRows ? `<table><thead><tr><th>Severity</th><th>Finding</th><th>Source</th><th>Status</th></tr></thead><tbody>${findingRows}</tbody></table>` : empty('findings', d.findingsError)}
</section>
<section>
  <h2>Brief me</h2>
  ${d.brief !== undefined ? analysisCard(d.brief, 'brief') : ''}
  <form method="post" action="/me/brief"><input type="hidden" name="csrf" value="${esc(ctx.csrf)}"><button class="btn ghost">What should I fix first?</button></form>
  <p class="muted small">The c0mpute analyst reads your open incidents and findings and says what to fix first. This sends them to an open model on the <a href="/go/c0mpute">c0mpute</a> peer network, with tokens, keys, passwords and email addresses removed first. Nothing is sent until you press the button.</p>
</section>
<section>
  <h2>Desktops</h2>
  <p>${d.desktops ? `${d.desktops} desktop${d.desktops === 1 ? '' : 's'} connected to your account.` : 'No desktop yet.'} A desktop gives your agent hands on your own computer, through the <a href="/go/w3bs">W3BS desktop layer</a> and a tunnel the desktop opens. <a href="/desktops">${d.desktops ? 'Manage desktops' : 'Add a desktop'}</a></p>
</section>
<section>
  <h2>Give this to your agent</h2>
  ${CONNECT}
</section>
<p class="small"><a href="/go/dashboard">Triage, teams, alerts and billing are in your ThreatCrush dashboard</a></p>`,
  })
}

export type DesktopView = Desktop & { live: { up: boolean; state?: string; error?: string } }

export function desktopsPage(ctx: Ctx, d: { desktops: DesktopView[]; tunnelHost: string; setup: (x: { port: number; brokerPort: number }) => string; error?: string; added?: Desktop }): string {
  const row = (x: DesktopView) => `<div class="card desktop">
  <p class="verdict ${x.live.up ? 'ok' : 'unknown'}"><span>${x.live.up ? 'Connected' : 'Not connected'}</span><b>${esc(x.name)}</b></p>
  <p class="muted small">Tunnel port <code>${x.port}</code>${x.live.state ? `, broker ${esc(x.live.state)}` : ''}${x.seenAt ? `, last seen ${esc(new Date(x.seenAt).toISOString().replace('T', ' ').slice(0, 16))} UTC` : ''}. Id <code>${esc(x.id)}</code></p>
  ${!x.live.up && x.live.error ? `<p class="small">${esc(x.live.error)}</p>` : ''}
  <details${d.added?.id === x.id || !x.live.up ? ' open' : ''}><summary>Set up this desktop</summary><pre><code>${esc(d.setup(x))}</code></pre></details>
  <form method="post" action="/desktops/${esc(x.id)}/delete"><input type="hidden" name="csrf" value="${esc(ctx.csrf)}"><button class="linkish">Remove this desktop (its key stops working at once)</button></form>
</div>`
  return layout({
    ctx,
    noindex: true,
    title: 'Desktops | security.agent',
    description: 'Give your AI agent hands on your own computer through the W3BS desktop layer and a tunnel your desktop opens.',
    path: '/desktops',
    body: `<h1>Desktops</h1>
<p class="tag">Some security work has to happen on your own computer: open the suspicious page in a real browser, click through an app's settings, take the 2FA prompt. A desktop gives your agent hands there through the <a href="/go/w3bs">W3BS Agentic Desktop Layer</a>, and you stay in charge of it.</p>
${d.error ? `<p class="error" role="alert">${esc(d.error)}</p>` : ''}
${d.added ? `<p class="ok-note" role="status">Added <b>${esc(d.added.name)}</b> on tunnel port <code>${d.added.port}</code>. Run step 3 below on that desktop to connect it.</p>` : ''}
${d.desktops.map(row).join('\n')}
<section>
  <h2>How it connects, both ways</h2>
  ${TUNNEL_DIAGRAM}
  <ol class="steps">
    <li><b>Desktop to server.</b> The desktop opens one outbound SSH connection to <code>${esc(d.tunnelHost)}</code> and asks it to listen on the desktop's own loopback port there (<code>ssh -R</code>). The desktop needs no open port, no public address and no VPN. The key can do nothing else on the server: no shell, no other forwards.</li>
    <li><b>Server to desktop.</b> When your agent calls a desktop tool, security.agent connects to that loopback port. SSH carries the call back down the same connection to the W3BS broker on the desktop's own <code>127.0.0.1:7801</code>, using the agent token you made for security.agent.</li>
    <li><b>You stay in charge.</b> The broker asks you before an agent drives, shows what it does, and stops on Super+Alt+Escape or from the tray. <code>systemctl --user disable --now security-agent-tunnel</code> cuts the connection. Removing the desktop here disables its key.</li>
  </ol>
  <p class="muted small">We run the same setup ourselves: our server dev2 reaches our desktop bonita through <code>ssh -N -R</code> from bonita, a systemd user unit that restarts forever. Here it carries the broker's MCP instead of a shell, and each desktop gets its own port.</p>
</section>
<section>
  <h2>Add a desktop</h2>
  <p class="muted small">On the desktop, run steps 1 and 2 first (the full script appears once the desktop is added), then paste the two values here.</p>
  <pre><code>curl -fsSL https://w3bs.org/desktop/install.sh | sh
w3bs desktop agents add security-agent --preset broad
ssh-keygen -t ed25519 -N '' -C security-agent-tunnel -f ~/.ssh/security-agent-tunnel</code></pre>
  <form method="post" action="/desktops" class="stack">
    <input type="hidden" name="csrf" value="${esc(ctx.csrf)}">
    <label>Name <input name="name" maxlength="60" placeholder="Work laptop"></label>
    <label>Tunnel public key <span class="muted">(~/.ssh/security-agent-tunnel.pub)</span><textarea name="public_key" rows="2" required placeholder="ssh-ed25519 AAAA… security-agent-tunnel" spellcheck="false"></textarea></label>
    <label>Agent token <span class="muted">(<code>cat ~/.config/w3bs/desktop/tokens/security-agent.token</code>; stored encrypted, used only to reach this desktop)</span><input name="token" type="password" required autocomplete="off" spellcheck="false"></label>
    <label>Broker port <span class="muted">(leave empty for 7801)</span><input name="broker_port" inputmode="numeric" placeholder="7801"></label>
    <button class="btn">Add desktop</button>
  </form>
</section>`,
  })
}

export function messagePage(ctx: Ctx, o: { title: string; message: string; action?: { href: string; label: string } }): string {
  return layout({
    ctx,
    noindex: true,
    title: `${o.title} | security.agent`,
    description: o.message,
    path: '/',
    body: `<section class="hero"><h1>${esc(o.title)}</h1><p class="tag">${esc(o.message)}</p><p><a class="btn" href="${esc(o.action?.href ?? '/')}">${esc(o.action?.label ?? 'Back to security.agent')}</a></p></section>`,
  })
}

/** /llms.txt: the site, for an agent that lands on it. */
export const llmsTxt = (origin: string) => `# security.agent

> A security team for your AI agent. security.agent connects agents to ThreatCrush (https://threatcrush.com): IP, domain and file reputation, and your organization's findings and incidents.

## Connect over MCP (preferred)
- MCP server (Streamable HTTP): ${TC_MCP}
- Auth: OAuth 2.1, public client, dynamic registration, PKCE S256, scope "mcp". Discovery: https://threatcrush.com/.well-known/oauth-authorization-server
- Or send a tc_agent_ key as the Bearer token.
- av_hash_lookup needs no credential.

## API on this site
- GET ${origin}/api/v1/check?q=<ip|domain|url|sha256>  (file hashes need no credential; others need Authorization: Bearer <ThreatCrush token or tc_agent_ key>)
- GET ${origin}/api/v1/findings, ${origin}/api/v1/incidents  (Bearer)
- GET ${origin}/api/v1/tools  (the live ThreatCrush tool list)

## CLI
- bunx ${NPM} login | check <indicator> | findings | incidents | mcp

## Engines
- Facts: ThreatCrush (above).
- Analysis: c0mpute, open models on peer nodes. GET /api/v1/check?q=…&explain=1, POST /api/v1/brief. "analysis": null means no node answered; the facts still stand.
- Your own computer: W3BS Agentic Desktop Layer (https://w3bs.org/desktop) on a desktop the user added, reached through an SSH tunnel the desktop opens (one outbound connection, used both ways). GET /api/v1/desktops, POST /api/v1/desktops/<id>/call {"tool": "...", "arguments": {...}}. Needs a person's OAuth token. Start with desktop_status; task_begin before any input; the person may be asked to approve; use human_step for CAPTCHAs, 2FA and passwords.

## Rules for agents
- Read tools are safe. findings_triage, incidents_update, incidents_raise and webhooks_* change shared state: confirm with your user first. incidents_raise pages people.
- "Not listed" means nobody reported it, not that it is safe.
- Send file hashes, never file contents.

## Protect the servers
- curl -fsSL https://threatcrush.com/install.sh | sh  (open source, MIT)
`

/**
 * The analyst: the thinking part of security.agent, run on c0mpute.
 *
 * ThreatCrush supplies the facts (is this listed, what was found, what was
 * raised). The analyst turns them into plain English and a next step, on the
 * c0mpute peer network through @profullstack/ai-providers. c0mpute only: no
 * paid model is ever called (AI_PAID_FALLBACK is forced off), and when no node
 * answers the facts are shown without the analysis, never a made-up one.
 *
 * Prompts go to c0mpute peer nodes. A public indicator's reputation is public
 * data, so it is explained by default. An organization's own findings and
 * incidents are not: they are sent only when the person asks for a brief, and
 * the page says where they go. Secrets are stripped first (redact()).
 */
import { createAiProviders } from '@profullstack/ai-providers'
import type { Check, Finding, Incident } from './threatcrush.js'

export type Analysis = { text: string; model: string; provider: string }
export type Generate = (req: { system: string; user: string; maxTokens: number; temperature?: number }) => Promise<{ text: string; model?: string; provider?: string }>

/**
 * Tried in order, one at a time. Measured on c0mpute 2026-11-25:
 *  - nemotron-3-nano:4b reasons before it answers: with a 120-token budget it came back empty, with
 *    800 it answered correctly in 15 to 35 s. So every call gets at least MIN_TOKENS.
 *  - The ai-providers router gives up on the whole provider when one model answers empty, so the
 *    walk down the list happens here, one router per model.
 *  - Which models have a live node changes by the minute; a missing one fails in under a second.
 *  - The uncensored 4B (huihui_ai/qwen3.5-abliterated:4b) told an agent to run known malware. It is
 *    not on this list.
 */
export const ANALYST_MODELS = 'nemotron-3-nano:4b,qwen3:4b-instruct-2507-q4_K_M,qwen3:4b,qwen3:8b,huihui_ai/qwen3.5-abliterated:9b'
const MIN_TOKENS = 800
/** A person is waiting on a page (Bun.serve's idle limit is 120 s). */
const DEADLINE_MS = 95_000

const routers = new Map<string, { generateText: Generate }>()
const routerFor = (model: string, timeoutMs: number) => {
  const key = `${model}:${Math.round(timeoutMs / 5000)}`
  let r = routers.get(key)
  if (!r) {
    r = createAiProviders({
      env: { ...process.env, AI_PAID_FALLBACK: 'off', C0MPUTE_MODELS: model },
      paidFallback: false,
      c0mpute: { timeoutMs, stallMs: Math.min(45_000, timeoutMs) },
    }) as unknown as { generateText: Generate }
    routers.set(key, r)
  }
  return r
}

const c0mpute = (): Generate => async (req) => {
  const models = (process.env.C0MPUTE_MODELS || ANALYST_MODELS).split(',').map((m) => m.trim()).filter(Boolean)
  const end = Date.now() + DEADLINE_MS
  let last: unknown = null
  for (const model of models) {
    const left = end - Date.now()
    if (left < 5_000) break
    try {
      const r = await routerFor(model, left).generateText({ ...req, maxTokens: Math.max(req.maxTokens, MIN_TOKENS) })
      if (r.text?.trim()) return { ...r, model: r.model || model }
    } catch (e) {
      last = e
    }
  }
  throw last instanceof Error ? last : new Error('no c0mpute model answered')
}

export const analystEnabled = () => !/^(1|true|yes|on)$/i.test(process.env.SECAGENT_ANALYST_OFF ?? '')

/** Strip what must never leave: tokens, keys, passwords, private key blocks, long secrets, emails. */
export function redact(text: string): string {
  return text
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[private key]')
    .replace(/\b(tc_(?:agent|oat|ort)_|ik_live_|ifc_|sk-|ghp_|gho_|github_pat_|xox[abp]-|AKIA)[A-Za-z0-9_\-]{8,}/g, '[secret]')
    .replace(/((?:password|passwd|secret|token|api[_-]?key|authorization)["'\s:=]+)[^\s"',;]{4,}/gi, '$1[secret]')
    .replace(/\b[A-Za-z0-9+/_-]{40,}={0,2}\b/g, (m) => (/^[0-9a-f]{64}$/i.test(m) ? m : '[long value]'))
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[email]')
}

const SYSTEM = `You are security.agent, a calm security analyst for people who run servers and AI agents.
Facts come from ThreatCrush. Use only the facts given; never invent addresses, malware names, CVEs or numbers.
"Not listed" means nobody reported it, not that it is safe. Unknown is not safe either.
Write plain English, no markdown headings, no more than the words asked for. End with one concrete next step.`

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}…` : s)

async function run(generate: Generate, user: string, maxTokens: number): Promise<Analysis | null> {
  if (!analystEnabled()) return null
  try {
    const r = await generate({ system: SYSTEM, user: redact(user), maxTokens, temperature: 0.2 })
    const text = String(r.text ?? '').replace(/^#+\s.*$/gm, '').trim()
    return text ? { text: clip(text, 1500), model: r.model ?? '', provider: r.provider ?? 'c0mpute' } : null
  } catch {
    return null
  }
}

/** What a check result means and what to do, in under 90 words. Public data only. */
export function explainCheck(r: Check, generate: Generate = c0mpute()): Promise<Analysis | null> {
  const facts = JSON.stringify({ indicator: r.indicator, kind: r.kind, verdict: r.verdict, summary: r.summary, score: r.score, details: r.details }).slice(0, 3000)
  return run(generate, `An AI agent is about to connect to, fetch, run or trust this ${r.kind === 'hash' ? 'file' : r.kind}. Explain in under 90 words what the ThreatCrush result means for it and whether to proceed.\n\nResult: ${facts}`, 220)
}

/** A short brief on an organization's open incidents and findings: what first, and why. Sent only when asked. */
export function brief(d: { incidents: Incident[]; findings: Finding[] }, generate: Generate = c0mpute()): Promise<Analysis | null> {
  const pick = (o: Record<string, unknown>, keys: string[]) => Object.fromEntries(keys.filter((k) => o[k] !== undefined && o[k] !== null).map((k) => [k, typeof o[k] === 'string' ? clip(o[k] as string, 200) : o[k]]))
  const incidents = d.incidents.slice(0, 12).map((i) => pick(i, ['severity', 'status', 'title', 'host', 'last_seen_at']))
  const findings = d.findings.slice(0, 20).map((f) => pick(f, ['severity', 'status', 'source', 'type', 'message', 'times_seen']))
  if (!incidents.length && !findings.length) return Promise.resolve(null)
  return run(generate, `Here are an organization's open ThreatCrush incidents and findings. In under 160 words: what to fix first and why, grouped where several share a cause. Then one next step.\n\nIncidents: ${JSON.stringify(incidents)}\n\nFindings: ${JSON.stringify(findings)}`, 380)
}

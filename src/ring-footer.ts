/**
 * The Profullstack webring footer (@profullstack/footer): our links, the copyright
 * and << Profullstack >>. It must be in the server-rendered HTML: rssamplifier's
 * ring verifier reads the page and never runs script, so a client-side footer never
 * counts. (The Moshpit ring bar at the top and the pit.world footer are separate.)
 *
 * Starts from the template bundled with the package, then re-reads the @latest
 * template in the background every 15 minutes, so a page never waits on the CDN and
 * a footer release reaches us without a redeploy. A failed read keeps the last copy.
 */
import { createHash } from 'node:crypto'
import { descriptor, footerHtml, footerHtmlSync, subscribeForm, type FooterOptions } from '@profullstack/footer'

/** The ring member URL (the web2 hostname; hops are measured from it). */
export const RING_SITE = 'https://security.agent.pit.world/'

const OPTIONS: FooterOptions = {
  site: RING_SITE,
  name: 'security.agent',
  links: [
    { label: 'Connect an agent', href: '/connect' },
    { label: 'Source', href: 'https://github.com/moshcoder/security.agent' },
    { label: 'Powered by ThreatCrush', href: '/go/threatcrush' },
    { label: 'c0mpute', href: '/go/c0mpute' },
    { label: 'W3BS desktop', href: '/go/w3bs' },
  ],
}

/**
 * The CSP source for the footer's inline newsletter script (wireSubscribe, since 0.4.0), as
 * 'sha256-...'. Our CSP has no 'unsafe-inline' and the footer is a cached string, so a per-request
 * nonce cannot reach it; the renderer (not the CDN template) emits the same bytes every time.
 */
export const FOOTER_SCRIPT_SRC: string = (() => {
  const m = subscribeForm(RING_SITE).match(/<script[^>]*>([\s\S]*?)<\/script>/)
  return m?.[1] ? `'sha256-${createHash('sha256').update(m[1]).digest('base64')}'` : ''
})()

let cached = footerHtmlSync(OPTIONS)

/** The footer HTML to print in the layout. */
export const ringFooter = (): string => cached

/** /.well-known/openwebring.json */
export const ringDescriptor = () => descriptor({ site: RING_SITE, name: 'security.agent' })

export function startRingFooterRefresh(everyMs = 15 * 60_000): () => void {
  const refresh = () =>
    footerHtml(OPTIONS)
      .then((html) => {
        if (typeof html === 'string' && html.includes('ring/profullstack')) cached = html
      })
      .catch(() => {})
  refresh()
  const timer = setInterval(refresh, everyMs)
  timer.unref?.()
  return () => clearInterval(timer)
}

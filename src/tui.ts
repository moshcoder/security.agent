/**
 * `securityagent` with no arguments: check things from the terminal.
 *
 * Type an IP address, a domain, a URL or a SHA-256 and press Enter. Answers
 * stack up, newest first. Esc clears the line, then quits.
 */
import { createApp } from '@profullstack/hqtui'
import { SecurityAgentClient } from './client.js'
import { AuthRequired, type Check } from './threatcrush.js'

export type TuiState = { input: string; busy: boolean; error: string | null; history: Check[] }

export const initialState = (): TuiState => ({ input: '', busy: false, error: null, history: [] })

/** Pure key handling, testable without a terminal. */
export function onKey(s: TuiState, key: { name: string; key: string; char?: string }): 'check' | 'quit' | null {
  if (key.key === 'ctrl+c') return 'quit'
  if (key.name === 'escape') return s.input ? ((s.input = ''), null) : 'quit'
  if (key.name === 'enter') return s.busy || !s.input.trim() ? null : 'check'
  if (key.name === 'backspace') s.input = s.input.slice(0, -1)
  else if (key.char && key.char.length === 1 && !key.key.startsWith('ctrl+') && s.input.length < 2048) s.input += key.char
  return null
}

const MARK: Record<Check['verdict'], string> = { malicious: '✗ MALICIOUS', suspicious: '! REPORTED ', clean: '✓ not listed', unknown: '? unknown   ' }

export async function runTui(client = new SecurityAgentClient()): Promise<void> {
  const s = initialState()
  const app = await createApp({ title: 'security.agent', quitKeys: [] })
  const check = async () => {
    const q = s.input.trim()
    s.busy = true
    s.error = null
    app.invalidate()
    try {
      s.history.unshift(await client.check(q))
      s.history.length = Math.min(s.history.length, 50)
      s.input = ''
    } catch (e) {
      s.error = e instanceof AuthRequired ? `${e.message}  Quit and run: securityagent login` : e instanceof Error ? e.message : String(e)
    } finally {
      s.busy = false
      app.invalidate()
    }
  }
  app.on('key', (event: any) => {
    const action = onKey(s, event)
    if (action === 'quit') app.quit()
    else if (action === 'check') void check()
    app.invalidate()
  })
  app.render(({ ui, theme }: any) => {
    const status = client.status()
    ui.row({ size: 1 }, (h: any) => {
      h.text(' security.agent', { fg: theme.accent, bold: true, size: 16 })
      h.text('a security team for your AI agent', { fg: theme.muted })
      h.text(`${status.via === 'api-key' ? 'agent key' : status.signedIn ? 'signed in' : 'not signed in: hashes only'} `, { fg: theme.muted, align: 'right' })
    })
    ui.panel({ title: s.busy ? 'Asking ThreatCrush…' : 'Check an IP, a domain, a URL or a SHA-256', size: 3 }, (p: any) => {
      p.text(`> ${s.input}▏`, { fg: theme.accent })
    })
    ui.panel({ title: 'Answers' }, (p: any) => {
      if (s.error) p.text(s.error, { fg: theme.danger ?? theme.accent })
      if (!s.history.length && !s.error) p.text('Nothing checked yet. File hashes need no sign-in; the rest needs `securityagent login`.', { fg: theme.muted })
      for (const r of s.history) {
        p.text(`${MARK[r.verdict]}  ${r.indicator}`, { fg: r.verdict === 'malicious' ? (theme.danger ?? theme.accent) : r.verdict === 'clean' ? theme.accent : theme.text, bold: true })
        p.text(`              ${r.summary}`, { fg: theme.muted })
      }
    })
    ui.statusBar({ items: [{ key: 'Enter', label: 'check' }, { key: 'Esc', label: s.input ? 'clear' : 'quit' }], right: [{ label: 'answers by ThreatCrush' }] })
  })
  await app.start()
}

/**
 * securityagent: security.agent from the terminal.
 *
 *   securityagent                      the TUI
 *   securityagent login | logout | status
 *   securityagent check <ip|domain|url|sha256>   or   check --file <path>
 *   securityagent findings [--status=…] [--severity=…]
 *   securityagent incidents [--status=…] [--host=…]
 *   securityagent tools                ThreatCrush's tool list
 *   securityagent call <tool> [json]   any ThreatCrush tool
 *   securityagent mcp                  MCP server on stdio
 *   securityagent serve [--port N]     run your own security.agent
 */
import { spawn } from 'node:child_process'
import { SecurityAgentClient } from './client.js'
import { AuthRequired, type Check } from './threatcrush.js'
import { VERSION } from './version.js'

export const HELP = `securityagent ${VERSION}: a security team for your AI agent, powered by ThreatCrush (https://security.agent)

  securityagent                     interactive (TUI)
  securityagent login               sign in with ThreatCrush: OAuth 2.1 in your browser.
                                    The token stays on this machine (~/.config/securityagent)
  securityagent logout              revoke the grant and forget the token
  securityagent status              how this machine is signed in
  securityagent check <indicator>   an IP address, a domain, a URL or a SHA-256 file hash.
                                    File hashes need no sign-in. Exit code 2 = malicious
  securityagent check --file <path> hash a file here and check the hash (the file is not sent)
  securityagent check <indicator> --explain
                                    and have the analyst (an open model on c0mpute) say what it means
  securityagent brief               what to fix first, written on c0mpute from your open incidents and
                                    findings (sends them, secrets stripped, to c0mpute peer nodes)
  securityagent desktops            your desktops (security.agent/desktops) and whether each tunnel is up
  securityagent desktop <id> <tool> ['{"json":"arguments"}']
                                    one W3BS desktop tool through the tunnel, e.g. desktop_status,
                                    desktop_screenshot, task_begin, mouse_click, human_step
  securityagent findings [--status=open,acknowledged] [--severity=critical,high] [--limit=25]
                                    what threatcrush scan, pentest and ai-scan found
  securityagent incidents [--status=open] [--host=name] [--limit=25]
                                    incidents raised to your team
  securityagent tools               every tool ThreatCrush offers an agent
  securityagent call <tool> ['{"json":"arguments"}']
                                    call any of them, e.g. findings_triage
  securityagent mcp                 MCP server: claude mcp add securityagent -- bunx @profullstack/securityagent mcp
  securityagent serve [--port N]    run your own instance of the website

  --json                            machine-readable output
  THREATCRUSH_API_KEY=tc_agent_…    use a ThreatCrush agent key instead of signing in (servers, CI)

  Protect the servers too: curl -fsSL https://threatcrush.com/install.sh | sh
`

type Out = { log(text: string): void; error(text: string): void }

const MARK: Record<Check['verdict'], string> = { malicious: '✗ MALICIOUS', suspicious: '! REPORTED', clean: '✓ not listed', unknown: '? unknown' }
export const checkLine = (r: Check) => `${MARK[r.verdict]}  ${r.indicator}\n  ${r.summary}`

/** Open the sign-in page in a browser if there is one; the URL is printed either way. */
function openBrowser(url: string): void {
  const command = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open'
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url]
  try {
    spawn(command, args, { stdio: 'ignore', detached: true }).on('error', () => {}).unref()
  } catch {}
}

const table = (rows: string[][]) => {
  const widths = rows[0]!.map((_, i) => Math.min(60, Math.max(...rows.map((r) => (r[i] ?? '').length))))
  return rows.map((r) => r.map((cell, i) => (i === r.length - 1 ? cell : cell.slice(0, 60).padEnd(widths[i]!))).join('  ')).join('\n')
}

export async function main(argv = process.argv.slice(2), out: Out = console, client = new SecurityAgentClient()): Promise<number> {
  const json = argv.includes('--json')
  const args = argv.filter((a) => !a.startsWith('--'))
  const flag = (name: string) => {
    const eq = argv.find((a) => a.startsWith(`--${name}=`))
    if (eq) return eq.slice(name.length + 3)
    const at = argv.indexOf(`--${name}`)
    return at >= 0 && argv[at + 1] && !argv[at + 1]!.startsWith('--') ? argv[at + 1] : undefined
  }
  const [command, ...rest] = args
  const show = (value: unknown, text: string) => out.log(json ? JSON.stringify(value, null, 2) : text)
  try {
    if (!command) {
      if (argv.includes('--version')) return out.log(VERSION), 0
      if (argv.includes('--help') || !process.stdout.isTTY) return out.log(HELP), 0
      const { runTui } = await import('./tui.js')
      await runTui(client)
      return 0
    }
    switch (command) {
      case 'help':
        return out.log(HELP), 0
      case 'version':
        return out.log(VERSION), 0
      case 'login': {
        await client.login((url) => {
          out.log(`Sign in with ThreatCrush in your browser:\n\n  ${url}\n\nWaiting for you to approve…`)
          if (!argv.includes('--no-open')) openBrowser(url)
        })
        return show({ signed_in: true }, 'Signed in. Try: securityagent check 1.1.1.1'), 0
      }
      case 'logout':
        return show({ signed_in: false }, (await client.logout()) ? 'Signed out: the grant is revoked and the token is gone.' : 'You were not signed in.'), 0
      case 'status': {
        const s = client.status()
        return show(s, s.via === 'api-key' ? 'Using THREATCRUSH_API_KEY.' : s.signedIn ? 'Signed in with ThreatCrush (OAuth).' : 'Not signed in. File hashes still work; run securityagent login for the rest.'), 0
      }
      case 'check': {
        const file = flag('file')
        // `check --file x` puts x in rest too: do not check it a second time as an indicator.
        const indicators = rest.filter((r) => r !== file)
        if (!file && !indicators.length) return out.error('Usage: securityagent check <ip|domain|url|sha256>   or   securityagent check --file <path>'), 1
        const results: Check[] = []
        if (file) results.push(await client.checkFile(file))
        for (const indicator of indicators) results.push(await client.check(indicator))
        if (argv.includes('--explain')) {
          const { explainCheck } = await import('./analyst.js')
          const explained = await Promise.all(results.map(async (r) => ({ ...r, analysis: await explainCheck(r) })))
          show(explained.length === 1 ? explained[0] : explained, explained.map((r) => `${checkLine(r)}\n\n  ${r.analysis ? `${r.analysis.text.replace(/\n/g, '\n  ')}\n  (c0mpute${r.analysis.model ? `, ${r.analysis.model}` : ''})` : '(no c0mpute node answered; the facts above stand)'}`).join('\n\n'))
        } else show(results.length === 1 ? results[0] : results, results.map(checkLine).join('\n'))
        return results.some((r) => r.verdict === 'malicious') ? 2 : 0
      }
      case 'brief': {
        const { brief } = await import('./analyst.js')
        const [findings, incidents] = await Promise.all([client.findings(), client.incidents({ status: 'open,acknowledged' })])
        out.error(`Sending ${incidents.length} incidents and ${findings.length} findings (secrets stripped) to an open model on c0mpute…`)
        const a = await brief({ findings, incidents })
        return show({ analysis: a, incidents: incidents.length, findings: findings.length }, a ? `${a.text}\n\n(c0mpute${a.model ? `, ${a.model}` : ''})` : incidents.length + findings.length ? 'No c0mpute node answered. Try again in a minute.' : 'Nothing open. Nothing to brief.'), 0
      }
      case 'desktops': {
        const r = await client.desktops()
        return show(r, r.desktops.length ? table([['ID', 'NAME', 'TUNNEL', 'STATE'], ...r.desktops.map((d) => [d.id, d.name, d.connected ? `up :${d.port}` : `down :${d.port}`, d.state ?? d.error ?? ''])]) : `No desktops. Add one at ${client.site}/desktops`), 0
      }
      case 'desktop': {
        const [id, tool, raw] = rest
        if (!id || !tool) return out.error('Usage: securityagent desktop <dt_id> <tool> [\'{"json":"arguments"}\']   e.g. desktop dt_x desktop_status'), 1
        let input: Record<string, unknown> = {}
        if (raw) {
          try {
            input = JSON.parse(raw) as Record<string, unknown>
          } catch {
            return out.error('The arguments must be one JSON object.'), 1
          }
        }
        const result = (await client.desktopCall(id, tool, input)) as { content?: { type: string; text?: string; data?: string }[] }
        if (!json && Array.isArray(result?.content)) return out.log(result.content.map((c) => (c.type === 'text' ? c.text : `[${c.type}${c.data ? `, ${Math.round((c.data.length * 3) / 4 / 1024)} KB` : ''}]`)).join('\n')), 0
        return out.log(JSON.stringify(result, null, 2)), 0
      }
      case 'findings': {
        const list = await client.findings({ ...(flag('status') ? { status: flag('status')! } : {}), ...(flag('severity') ? { severity: flag('severity')! } : {}), ...(flag('limit') ? { limit: Number(flag('limit')) } : {}) })
        return show(list, list.length ? table([['SEVERITY', 'STATUS', 'SOURCE', 'FINDING'], ...list.map((f) => [String(f.severity ?? ''), String(f.status ?? ''), String(f.source ?? ''), String(f.message ?? f.title ?? f.id)])]) : 'No findings. Run threatcrush scan, pentest or ai-scan while signed in and they land here.'), 0
      }
      case 'incidents': {
        const list = await client.incidents({ ...(flag('status') ? { status: flag('status')! } : {}), ...(flag('host') ? { host: flag('host')! } : {}), ...(flag('limit') ? { limit: Number(flag('limit')) } : {}) })
        return show(list, list.length ? table([['SEVERITY', 'STATUS', 'HOST', 'INCIDENT'], ...list.map((i) => [String(i.severity ?? ''), String(i.status ?? ''), String(i.host ?? ''), String(i.title ?? i.id)])]) : 'No incidents.'), 0
      }
      case 'tools': {
        const list = await client.tools()
        return show(list, list.map((t) => `${t.name}\n  ${String(t.description ?? '').replace(/\s+/g, ' ').slice(0, 200)}`).join('\n')), 0
      }
      case 'call': {
        if (!rest[0]) return out.error('Usage: securityagent call <tool> [\'{"json":"arguments"}\']'), 1
        let input: Record<string, unknown> = {}
        if (rest[1]) {
          try {
            input = JSON.parse(rest[1]) as Record<string, unknown>
          } catch {
            return out.error('The arguments must be one JSON object, e.g. \'{"ids":["…"],"status":"fixed"}\''), 1
          }
        }
        const result = await client.call(rest[0], input)
        return out.log(typeof result === 'string' ? result : JSON.stringify(result, null, 2)), 0
      }
      case 'mcp': {
        const { runMcp } = await import('./mcp.js')
        await runMcp(client)
        return 0
      }
      case 'serve': {
        const { serve } = await import('./server.js')
        const server = serve({ ...(flag('port') ? { port: Number(flag('port')) } : {}) })
        out.log(`security.agent listening on http://${server.hostname}:${server.port}`)
        await new Promise(() => {})
        return 0
      }
      default:
        // `securityagent 1.2.3.4` is a check.
        if (args.length === 1) return main(['check', ...argv], out, client)
        return out.error(`Unknown command: ${command}\n\n${HELP}`), 1
    }
  } catch (e) {
    if (e instanceof AuthRequired) return out.error(`${e.message}\n\nSign in:  securityagent login   (or set THREATCRUSH_API_KEY=tc_agent_…)\nNo account? It is free: https://threatcrush.com/?utm_source=security.agent&utm_medium=cli`), 3
    return out.error(e instanceof Error ? e.message : String(e)), 1
  }
}

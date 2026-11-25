/**
 * `securityagent mcp`: security.agent for an agent, on stdio.
 *
 *   claude mcp add securityagent -- bunx @profullstack/securityagent mcp
 *
 * It uses this machine's ThreatCrush sign-in (`securityagent login`, OAuth 2.1)
 * or THREATCRUSH_API_KEY. File hashes need neither. An agent that can speak
 * remote MCP can skip this and connect to https://threatcrush.com/api/mcp.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { explainCheck } from './analyst.js'
import { SecurityAgentClient } from './client.js'
import { AuthRequired } from './threatcrush.js'
import { VERSION } from './version.js'

const text = (value: unknown) => ({ content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }] })
const failure = (error: unknown) => ({
  isError: true,
  content: [{ type: 'text', text: error instanceof AuthRequired ? `${error.message} Ask the user to run \`securityagent login\` (sign in with ThreatCrush, OAuth 2.1) or to set THREATCRUSH_API_KEY, then try again.` : error instanceof Error ? error.message : String(error) }],
})

export function createMcpServer(client = new SecurityAgentClient()): McpServer {
  const server: any = new McpServer({ name: 'security.agent', version: VERSION })
  const run = async (work: () => Promise<unknown>) => {
    try {
      return text(await work())
    } catch (e) {
      return failure(e)
    }
  }
  server.tool(
    'check',
    'Before you fetch, call, install or trust something: check an IP address, a domain, a URL (its host is checked) or a SHA-256 file hash against ThreatCrush. Returns verdict (malicious, suspicious, clean or unknown), a one-line summary, a 0-100 score and the details. "clean" means nobody reported it, not that it is safe. File hashes need no sign-in.',
    { indicator: z.string().min(1).max(2048).describe('An IP address, a domain, a URL or a lower-case hex SHA-256 file hash') },
    ({ indicator }: { indicator: string }) => run(() => client.check(indicator)),
  )
  server.tool(
    'check_file',
    'Hash a local file (SHA-256, computed on this machine) and check the hash against ThreatCrush CrushAV. The file itself is never sent. Use before running a downloaded binary or script.',
    { path: z.string().min(1).describe('Path to the file on this machine') },
    ({ path }: { path: string }) => run(() => client.checkFile(path)),
  )
  server.tool(
    'findings',
    "The signed-in organization's tracked findings from threatcrush scan, pentest and ai-scan. Default: open and acknowledged.",
    { status: z.string().optional().describe('Comma list of open, acknowledged, fixed, false_positive, ignored, or all'), severity: z.string().optional().describe('Comma list of critical, high, medium, low, info'), limit: z.number().int().min(1).max(500).optional() },
    (a: { status?: string; severity?: string; limit?: number }) => run(() => client.findings(a)),
  )
  server.tool(
    'incidents',
    "The signed-in organization's incidents: what the ThreatCrush daemon and people raised to humans.",
    { status: z.string().optional().describe('Comma list of open, acknowledged, resolved, or all'), host: z.string().optional().describe('Only incidents on a host whose name contains this'), limit: z.number().int().min(1).max(500).optional() },
    (a: { status?: string; host?: string; limit?: number }) => run(() => client.incidents(a)),
  )
  server.tool('threatcrush_tools', 'Every tool ThreatCrush offers (names, descriptions, input schemas), for use with threatcrush_call.', {}, () => run(() => client.tools()))
  server.tool(
    'threatcrush_call',
    'Call any ThreatCrush tool by name as the signed-in user: findings_get, findings_triage, incidents_get, incidents_update, reputation_bulk, webhooks_list and the rest (see threatcrush_tools). findings_triage, incidents_update, incidents_raise and the webhooks_ write tools change what the team sees, and incidents_raise pages people by SMS and email: confirm with the user before calling those.',
    { name: z.string().regex(/^[a-z0-9_]{1,64}$/), arguments: z.record(z.string(), z.unknown()).optional() },
    (a: { name: string; arguments?: Record<string, unknown> }) => run(() => client.call(a.name, a.arguments ?? {})),
  )
  server.tool(
    'explain',
    'Check an indicator, then have the security.agent analyst (an open model on the c0mpute peer network) say in plain English what the result means and whether to proceed. Slower than check (up to ~100 s); analysis is null when no c0mpute node answered, and the facts still stand.',
    { indicator: z.string().min(1).max(2048) },
    ({ indicator }: { indicator: string }) =>
      run(async () => {
        const result = await client.check(indicator)
        return { ...result, analysis: await explainCheck(result) }
      }),
  )
  server.tool(
    'desktops',
    "The user's own computers added at security.agent/desktops, and whether each one's tunnel is up. A desktop runs the W3BS Agentic Desktop Layer and opens one outbound SSH connection to security.agent; desktop calls travel back down it. Use a desktop only for work that must happen on the user's machine (look at a page in their browser, click through an app, hand them a 2FA step), never for lookups check can answer.",
    {},
    () => run(() => client.desktops()),
  )
  server.tool(
    'desktop_call',
    "Call one W3BS desktop tool on one of the user's desktops: desktop_status, desktop_windows, desktop_screenshot, desktop_inspect, task_begin (required before any input), mouse_click, keyboard_type, keyboard_shortcut, input_batch, human_step (CAPTCHA, 2FA, passwords: hand them to the person), task_end and the rest. The person at the desktop may be asked to approve first (approval_status), sees what you do, and can stop you. Never type secrets you were not given; use human_step.",
    { desktop: z.string().regex(/^dt_[A-Za-z0-9_-]{6,40}$/).describe('Desktop id from desktops'), tool: z.string().regex(/^[a-z_]{3,40}$/), arguments: z.record(z.string(), z.unknown()).optional() },
    (a: { desktop: string; tool: string; arguments?: Record<string, unknown> }) => run(() => client.desktopCall(a.desktop, a.tool, a.arguments ?? {})),
  )
  server.tool('status', 'Whether this machine is signed in to ThreatCrush, and how.', {}, () => run(async () => client.status()))
  return server as McpServer
}

export async function runMcp(client = new SecurityAgentClient()): Promise<void> {
  const server = createMcpServer(client)
  await server.connect(new StdioServerTransport())
  await new Promise<void>((resolve) => {
    process.stdin.on('close', resolve)
    process.stdin.on('end', resolve)
  })
}

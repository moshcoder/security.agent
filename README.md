# security.agent

A security team for your AI agent. Sign in with [ThreatCrush](https://threatcrush.com) and give any agent (Claude, ChatGPT, Codex, your own) a place to ask: is this address attacking people, is this domain on a blocklist, is this file malware, what is open on my servers, and what should I fix first.

Live at **https://security.agent.pit.world** (and `https://security.agent` on Moshpit DNS). MIT.

## Three engines under the hood

| Ask | Answered by |
|---|---|
| Is this IP, domain, URL or file bad? What was found or raised on my servers? | **ThreatCrush**: every fact, through its MCP server, as the signed-in person |
| What does this mean? What do I fix first? | **c0mpute**: open models on the peer network (`@profullstack/ai-providers`), only when asked. No paid model, and nothing made up when no node answers |
| Do something on my own computer: open a page in my browser, click through an app, hand me a 2FA prompt | **W3BS desktop** ([w3bs.org/desktop](https://w3bs.org/desktop)): through a tunnel the desktop opens, with the person's approval |

## Sign in: ThreatCrush OAuth 2.1

ThreatCrush is the authorization server: public clients, dynamic client registration (RFC 7591), authorization code + PKCE S256, rotating refresh tokens, scope `mcp`, `iss` checked on the callback (RFC 9207). The site registers itself once and keeps the client id. Tokens are sealed (AES-256-GCM) in SQLite under `SECAGENT_KEY`; signing out revokes the grant at ThreatCrush. The CLI signs in with a loopback redirect (RFC 8252) and keeps its token on that machine only.

## Desktops: one connection, both ways

A signed-in person can add a desktop. It runs the W3BS Agentic Desktop Layer (broker MCP on `127.0.0.1:7801`) and opens **one outbound SSH connection** to the security.agent host:

```
desktop ──ssh -N -R localhost:<port>:127.0.0.1:7801──▶ secagent-tunnel@dev2      (1) desktop to server
desktop ◀── agent's MCP calls ride back down the same connection ── 127.0.0.1:<port>  (2) server to desktop
```

1. **Desktop to server.** A systemd user unit on the desktop dials out and asks sshd to listen on that desktop's own loopback port. The desktop needs no open port, public address or VPN. Its key can do one thing on the server (`restrict,port-forwarding,permitlisten="localhost:<port>",permitopen="none",command="/bin/false"`): no shell, no other forwards.
2. **Server to desktop.** A desktop tool call from the person's agent (`/api/v1/desktops/<id>/call`, MCP `desktop_call`) connects to that port. SSH carries it back to the broker on the desktop with the agent token the person made (`w3bs desktop agents add security-agent`). security.agent sends `Host: 127.0.0.1:7801` itself and never an `Origin`, as the broker requires.
3. **The person stays in charge.** The broker asks before an agent drives and shows what it does. It stops on Super+Alt+Escape or from the tray. `systemctl --user disable --now security-agent-tunnel` cuts the connection. Removing the desktop on the site drops its key from sshd at once.

This is the setup our server dev2 already has with our desktop bonita (`dev2-tunnel.service` on bonita, `ssh -N -R 2222:localhost:22`). Here it carries the broker's MCP instead of a shell, with one port per desktop.

Desktops belong to the person's ThreatCrush account (`list_invites` names the caller). A `tc_agent_` key belongs to a team, not a person, so it cannot reach desktops.

Host setup, once, as root: `sh deploy/tunnel/setup.sh`. It creates the `secagent-tunnel` user, the sshd `Match` block and the `AuthorizedKeysCommand` that serves the app's key file, and it runs `sshd -t` before reloading.

## Surfaces

- **Web**: `/` check box, `/connect`, `/me` dashboard (findings, incidents, "what should I fix first"), `/desktops`.
- **API**: `GET /api/v1/check?q=…[&explain=1]`, `/api/v1/findings`, `/api/v1/incidents`, `POST /api/v1/brief`, `GET /api/v1/desktops`, `POST /api/v1/desktops/:id/call`, `/api/v1/tools`. Bearer = a ThreatCrush OAuth token or `tc_agent_` key, passed through and not stored. File hashes need no credential.
- **MCP (remote)**: point any agent at `https://threatcrush.com/api/mcp` and it signs in with OAuth.
- **CLI / TUI / MCP (stdio)**: `bunx @profullstack/securityagent` (TUI), `login`, `check <x> [--explain]`, `check --file <path>`, `findings`, `incidents`, `brief`, `desktops`, `desktop <id> <tool> [json]`, `call <tool> [json]`, `mcp`. Exit code 2 means malicious.

## Run it

```sh
bun install
SECAGENT_KEY=$(openssl rand -hex 32) bun src/server.ts   # :8799
bun test && bunx tsc --noEmit
```

| Env | |
|---|---|
| `SECAGENT_KEY` | seals tokens and signs CSRF (required) |
| `SECAGENT_DB` | SQLite path |
| `SECAGENT_ADMIN_KEY` | Bearer for `/api/v1/stats` (the funnel, totals per day) |
| `SECAGENT_TUNNEL_HOST`, `SECAGENT_TUNNEL_USER`, `SECAGENT_TUNNEL_KEYS` | where desktops dial in, and the keys file sshd reads |
| `C0MPUTE_API_KEY` | Infernet account key (`ik_live_…`); without it the analyst shares the free tier |
| `C0MPUTE_MODELS` | analyst models, default instruct models first (`nemotron-3-nano:4b,…`) |
| `SECAGENT_ANALYST_OFF=1` | facts only |
| `CRAWLPROOF_SITE`, `CRAWLPROOF_AD_SLOT` | analytics and one text-link ad on `/connect` (off by default) |

## Privacy

Nothing that was looked up is stored, only daily totals. A public indicator's reputation can go to c0mpute when someone presses "explain". An organization's findings and incidents go to c0mpute only when the person presses "What should I fix first?". Tokens, keys, passwords and email addresses are stripped first.

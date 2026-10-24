/**
 * dsh-lan-access — password-protected LAN web access for the DeepSeek Harness Web GUI.
 *
 * The built-in HTTP carrier binds loopback only, and its Host/Origin fence
 * rejects remote authorities, so another device cannot open the GUI directly.
 * This plugin runs a second plain Node HTTP server on a configurable address
 * (default 0.0.0.0:8848) and reverse-proxies HTTP and WebSocket traffic to the
 * loopback listener, rewriting Host / Origin / Referer to the loopback
 * authority so the fence passes.
 *
 * Access on the LAN port uses a website-style password login: a visitor
 * without a session gets a login page, submits the password, and the plugin
 * performs DSH's launch-token exchange server-side, forwarding only the
 * signed session cookie to the browser. The launch token itself is never
 * shown to visitors. The panel on the loopback server (/_lan-access, admitted
 * to an authenticated owner browser only) lists the LAN addresses and shows
 * or regenerates the generated password; the LAN listener never serves it.
 */
import { createServer, request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir, networkInterfaces } from 'node:os'
import { join } from 'node:path'
import { URL } from 'node:url'

export const inject = ['webServer', 'connection']

const PANEL_PATH = '/_lan-access'
const PANEL_RESET_PATH = '/_lan-access/reset'
const LOGIN_PATH = '/_lan-login'
const DEFAULT_PORT = 8848
const PASSWORD_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
const MAX_LOGIN_BODY = 4096
const FAILURE_WINDOW_MS = 60_000
const FAILURE_LIMIT = 5
const FAILURE_DELAY_MS = 400

/** Headers that belong to a single hop and must not be relayed verbatim. */
const HOP_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade',
  'content-length', 'expect',
])

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]
  ))
}

function randomPassword(length = 12) {
  const bytes = randomBytes(length)
  let out = ''
  for (let i = 0; i < length; i++) out += PASSWORD_ALPHABET[bytes[i] % PASSWORD_ALPHABET.length]
  return out
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left), 'utf8')
  const b = Buffer.from(String(right), 'utf8')
  const length = Math.max(a.length, b.length)
  const pa = Buffer.alloc(length)
  const pb = Buffer.alloc(length)
  a.copy(pa)
  b.copy(pb)
  return timingSafeEqual(pa, pb)
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/** Deterministic name of the DSH browser-session cookie for one authority. */
function sessionCookieName(authority) {
  return 'dsh-auth-' + createHash('sha256').update(authority).digest('base64url')
}

/** Read the issue timestamp out of a signed cookie value without the secret. */
function cookieIssuedAt(cookieValue) {
  try {
    const parts = String(cookieValue).split('.')
    if (parts.length !== 3 || (parts[0] !== 'v1' && parts[0] !== 'v2')) return undefined
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
    return typeof payload.issuedAt === 'number' && Number.isFinite(payload.issuedAt) ? payload.issuedAt : undefined
  } catch {
    return undefined
  }
}

/**
 * Drop session cookies minted before the cutoff (sessions revoked by a
 * password reset). Signature verification stays with the upstream server;
 * this check only removes cookies that are provably too old, so a stale
 * client is sent back to the login page instead of reusing its session.
 */
function stripStaleCookies(cookieHeader, authority, sessionCutoff) {
  if (!cookieHeader || !Number.isFinite(sessionCutoff) || sessionCutoff <= 0) return cookieHeader
  const name = sessionCookieName(authority)
  let changed = false
  const segments = String(cookieHeader).split(';').filter((segment) => {
    const at = segment.indexOf('=')
    if (at === -1) return true
    if (segment.slice(0, at).trim() !== name) return true
    const issuedAt = cookieIssuedAt(segment.slice(at + 1).trim())
    if (issuedAt === undefined || issuedAt >= sessionCutoff) return true
    changed = true
    return false
  })
  return changed ? segments.join(';') : cookieHeader
}

function isLinkLocalIpv4(address) {
  const [a, b] = address.split('.').map(Number)
  return a === 169 && b === 254
}

function isPrivateIpv4(address) {
  const [a, b] = address.split('.').map(Number)
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}

function lanIpv4Addresses() {
  const found = []
  for (const [label, interfaces] of Object.entries(networkInterfaces())) {
    for (const info of interfaces ?? []) {
      if (info.internal || info.family !== 'IPv4') continue
      const ip = info.address
      if (isLinkLocalIpv4(ip)) continue
      found.push({ ip, label })
    }
  }
  found.sort((left, right) => {
    const lp = isPrivateIpv4(left.ip) ? 0 : 1
    const rp = isPrivateIpv4(right.ip) ? 0 : 1
    return lp - rp || left.ip.localeCompare(right.ip, 'en', { numeric: true })
  })
  return found
}

function requestPathname(req) {
  try {
    return new URL(req.url ?? '/', 'http://placeholder').pathname
  } catch {
    return '/'
  }
}

function isPanelPath(pathname) {
  return pathname === PANEL_PATH || pathname.startsWith(`${PANEL_PATH}/`)
}

function strippedHeaders(headers) {
  const out = {}
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue
    if (HOP_HEADERS.has(key.toLowerCase())) continue
    out[key] = value
  }
  return out
}

function rewriteOutgoingHeaders(headers, upstream) {
  const out = strippedHeaders(headers)
  out.host = upstream.host
  if (typeof out.origin === 'string') out.origin = upstream.origin
  if (typeof out.referer === 'string') {
    try {
      const url = new URL(out.referer)
      url.protocol = upstream.protocol
      url.host = upstream.host
      out.referer = url.href
    } catch {
      /* keep the original value */
    }
  }
  return out
}

function upgradeHeaders(headers, upstream) {
  const out = strippedHeaders(headers)
  out.host = upstream.host
  out.connection = 'Upgrade'
  if (typeof headers.upgrade === 'string') out.upgrade = headers.upgrade
  if (typeof out.origin === 'string') out.origin = upstream.origin
  return out
}

function passwordFilePath() {
  const home = process.env.DSH_HOME || join(homedir(), '.dsh')
  return join(home, '.dsh-lan-access.json')
}

/** Load the configured password, or the persisted generated one (created on first run). */
function resolvePasswordState(config) {
  const configured = typeof config.password === 'string' && config.password !== ''
  const file = passwordFilePath()
  let existing = {}
  try {
    if (existsSync(file)) existing = JSON.parse(readFileSync(file, 'utf8')) ?? {}
  } catch (error) {
    throw new Error(`dsh-lan-access: cannot read password file ${file}: ${error instanceof Error ? error.message : String(error)}`)
  }
  const persist = (data) => {
    try {
      writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`)
    } catch (error) {
      throw new Error(`dsh-lan-access: cannot write password file ${file}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  const validCutoff = (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : undefined
  const now = Date.now()

  if (configured) {
    // Config-managed password: rotate the session cutoff whenever the
    // configured value changes, so a new config password also revokes
    // sessions of devices that used the previous one.
    const hash = createHash('sha256').update(config.password, 'utf8').digest('hex')
    let sessionCutoff = validCutoff(existing.sessionCutoff) ?? 0
    if (existing.passwordHash !== hash) {
      sessionCutoff = now
      persist({ passwordHash: hash, sessionCutoff })
    }
    return { configured: true, password: config.password, file, sessionCutoff }
  }

  if (typeof existing.password === 'string' && existing.password !== '') {
    let sessionCutoff = validCutoff(existing.sessionCutoff)
    if (sessionCutoff === undefined) {
      // File from before session revocation existed: revoke everything minted
      // so far once, and persist the cutoff so restarts do not reset it.
      sessionCutoff = now
      persist({ password: existing.password, sessionCutoff })
    }
    return { configured: false, password: existing.password, file, sessionCutoff }
  }

  const password = randomPassword()
  persist({ password, sessionCutoff: now })
  return { configured: false, password, file, sessionCutoff: now }
}

/** Website-style login page; `action` picks the route that processes the form. */
function loginPage({ error = '', locked = false, action = LOGIN_PATH, hint = '' } = {}) {
  const message = locked
    ? '<p class="err">尝试次数过多，请 1 分钟后再试。</p>'
    : error !== ''
      ? `<p class="err">${escapeHtml(error)}</p>`
      : ''
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeepSeek Harness · 登录</title>
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background: #10131a; color: #e6e9f0; display: flex; min-height: 100vh; margin: 0; align-items: center; justify-content: center; }
  .card { width: 360px; max-width: 90vw; margin: 24px; padding: 32px; background: #171b26; border: 1px solid #2a3142; border-radius: 14px; }
  h1 { margin: 0 0 6px; font-size: 20px; }
  .sub { margin: 0 0 20px; color: #9aa3b8; font-size: 13px; }
  label { display: block; font-size: 13px; color: #b6bdd0; margin-bottom: 8px; }
  input { box-sizing: border-box; width: 100%; background: #0e1118; color: #e6e9f0; border: 1px solid #2a3142; border-radius: 8px; padding: 10px 12px; font-size: 15px; }
  input:focus { outline: none; border-color: #4d6bfe; }
  button { width: 100%; margin-top: 16px; background: #2b3a5e; color: #dfe6ff; border: none; border-radius: 8px; padding: 10px; cursor: pointer; font-size: 15px; }
  button:hover { background: #38507f; }
  .err { color: #ff8b8b; font-size: 13px; margin: 12px 0 0; }
  .hint { margin: 18px 0 0; font-size: 12px; color: #8b93a8; line-height: 1.7; }
  .hint code { background: #232a3b; padding: 2px 6px; border-radius: 5px; color: #9db4ff; word-break: break-all; }
</style>
</head>
<body>
<div class="card">
  <h1>DeepSeek Harness</h1>
  <p class="sub">请输入访问密码</p>
  <form method="post" action="${escapeHtml(action)}">
    <label for="password">密码</label>
    <input id="password" name="password" type="password" required autofocus autocomplete="current-password" placeholder="访问密码">
    <button type="submit">登录</button>
    ${message}
  </form>
  <p class="hint">忘记密码？${hint}</p>
</div>
</body>
</html>`
}

/** Owner-facing panel on the loopback server. */
function renderPanel({ bindHost, port, panelUrl, upstreamOrigin, links, password, passwordConfigured, resetNote = '' }) {
  const rows = links.length === 0
    ? `<p class="warn">未检测到局域网 IPv4 地址。请确认电脑已连接路由器 / Wi-Fi，然后刷新本页。</p>`
    : links.map(({ ip, label, url }) => `
      <div class="row">
        <div class="ip">${escapeHtml(ip)}<span class="iface">${escapeHtml(label)}</span></div>
        <input class="url" readonly value="${escapeHtml(url)}">
        <button type="button" data-copy="${escapeHtml(url)}">复制网址</button>
        <button type="button" data-open="${escapeHtml(url)}">打开</button>
      </div>`).join('')
  const passwordSection = passwordConfigured
    ? `<p class="pw">访问密码由插件配置的 <code>password</code> 字段指定。</p>`
    : `<div class="pw"><span>访问密码</span><code id="pw-value" data-actual="${escapeHtml(password)}" data-hidden="true">••••••••</code>
         <button type="button" id="pw-reveal">显示</button>
         <button type="button" data-copy="${escapeHtml(password)}">复制</button>
       </div>
       <form method="post" action="/_lan-access/reset" class="pwform">
         <input class="pw-input" type="password" name="password" placeholder="当前密码" required autocomplete="current-password">
         <input class="pw-input" type="password" name="newPassword" placeholder="新密码（至少 6 位）" autocomplete="new-password">
         <input class="pw-input" type="password" name="confirmPassword" placeholder="确认新密码" autocomplete="new-password">
         <button type="submit" name="mode" value="set">保存自定义密码</button>
         <button type="submit" name="mode" value="generate" class="danger">随机重新生成</button>
       </form>`
  const note = resetNote === ''
    ? ''
    : `<p class="note ${resetNote.startsWith('已') ? 'ok' : 'bad'}">${escapeHtml(resetNote)}</p>`
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DSH 局域网访问</title>
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background: #10131a; color: #e6e9f0; margin: 0; padding: 32px 16px; }
  .wrap { max-width: 880px; margin: 0 auto; }
  h1 { font-size: 22px; margin: 0 0 6px; }
  .sub { color: #9aa3b8; margin: 0 0 24px; line-height: 1.6; }
  .status { font-size: 13px; color: #8b93a8; margin-bottom: 20px; }
  .status code { background: #232a3b; padding: 2px 8px; border-radius: 6px; color: #9db4ff; }
  .pw { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; background: #171b26; border: 1px solid #2a3142; border-radius: 12px; padding: 12px 14px; margin-bottom: 12px; font-size: 14px; }
  .pw code { background: #232a3b; padding: 4px 10px; border-radius: 6px; color: #9db4ff; font-family: ui-monospace, Consolas, monospace; }
  .pw form { margin: 0; }
  .pwform { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; background: #171b26; border: 1px solid #2a3142; border-radius: 12px; padding: 12px 14px; margin-bottom: 12px; }
  .pw-input { background: #0e1118; color: #e6e9f0; border: 1px solid #2a3142; border-radius: 8px; padding: 8px 10px; font-size: 13px; width: 170px; }
  .pw-input:focus { outline: none; border-color: #4d6bfe; }
  .note { margin: 0 0 12px; font-size: 13px; }
  .note.ok { color: #7ddc8a; }
  .note.bad { color: #ff8b8b; }
  .row { display: grid; grid-template-columns: 190px 1fr auto auto; gap: 10px; align-items: center; background: #171b26; border: 1px solid #2a3142; border-radius: 12px; padding: 12px 14px; margin-bottom: 10px; }
  .ip { font-weight: 600; font-family: ui-monospace, Consolas, monospace; }
  .iface { display: block; font-size: 11px; color: #8b93a8; font-weight: 400; margin-top: 2px; }
  input.url { min-width: 0; background: #0e1118; color: #c7cfe3; border: 1px solid #2a3142; border-radius: 8px; padding: 8px 10px; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
  button { white-space: nowrap; background: #2b3a5e; color: #dfe6ff; border: none; border-radius: 8px; padding: 8px 14px; cursor: pointer; font-size: 13px; }
  button:hover { background: #38507f; }
  button.danger { background: #5e2b2b; }
  button.danger:hover { background: #7f3838; }
  .tips { margin-top: 26px; background: #171b26; border: 1px solid #2a3142; border-radius: 12px; padding: 16px 18px; color: #b6bdd0; font-size: 13px; line-height: 1.8; }
  .tips code { background: #232a3b; padding: 2px 8px; border-radius: 6px; color: #9db4ff; word-break: break-all; }
  .warn { color: #ffb86b; }
</style>
</head>
<body>
<div class="wrap">
  <h1>局域网访问</h1>
  <p class="sub">在手机、平板或同一网络下的其他电脑上打开下面的网址，输入访问密码即可使用本程序的网页界面。</p>
  <div class="status">
    监听地址 <code>${escapeHtml(bindHost)}:${String(port)}</code> → 转发到 <code>${escapeHtml(upstreamOrigin)}</code> ·
    面板地址 <code>${escapeHtml(panelUrl)}</code>
  </div>
  ${note}
  ${passwordSection}
  ${rows}
  <div class="tips">
    <p>请选择与其他设备处于同一网络的接口（通常是 WLAN / 以太网）；蓝牙共享、WSL 等接口的地址其他设备往往无法访问。</p>
    <p>可自定义密码或随机重新生成；修改后之前已登录设备的会话会<strong>立即失效</strong>，需要用新密码重新登录；本机面板不受影响。</p>
    <p>其他设备无法访问时，请在<strong>运行本程序的电脑</strong>上放行防火墙端口（管理员权限执行）：</p>
    <p><code>netsh advfirewall firewall add rule name="DSH LAN Access" dir=in action=allow protocol=TCP localport=${String(port)}</code></p>
    <p>局域网内为明文 HTTP，请仅在信任的网络中使用，或使用系统防火墙限制来源。</p>
  </div>
</div>
<script>
for (const button of document.querySelectorAll('button[data-copy]')) {
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy)
      button.textContent = '已复制'
    } catch {
      button.textContent = '复制失败'
    }
    setTimeout(() => { button.textContent = '复制' }, 1500)
  })
}
for (const button of document.querySelectorAll('button[data-open]')) {
  button.addEventListener('click', () => {
    window.open(button.dataset.open, '_blank', 'noopener')
  })
}
const reveal = document.getElementById('pw-reveal')
if (reveal) {
  reveal.addEventListener('click', () => {
    const value = document.getElementById('pw-value')
    const hidden = value.dataset.hidden === 'true'
    value.textContent = hidden ? value.dataset.actual : '••••••••'
    value.dataset.hidden = hidden ? 'false' : 'true'
    reveal.textContent = hidden ? '隐藏' : '显示'
  })
}
</script>
</body>
</html>`
}

export function apply(ctx, config = {}) {
  const bindHost = typeof config.host === 'string' && config.host.trim() !== '' ? config.host.trim() : '0.0.0.0'
  const port = Number(config.port ?? DEFAULT_PORT)
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`dsh-lan-access: port ${JSON.stringify(config.port)} must be an integer between 0 and 65535`)
  }

  const upstream = new URL(ctx.webServer.getOrigin())
  const panelUrl = `${upstream.href.replace(/\/+$/, '')}${PANEL_PATH}`
  const passwordState = resolvePasswordState(config)
  const failures = []

  const passwordRecoveryHint = passwordState.configured
    ? '密码由插件配置的 <code>password</code> 字段指定，修改请编辑插件配置。'
    : `密码保存在运行本程序的电脑上：<code>${escapeHtml(passwordState.file)}</code>，登录面板后也可查看或重置。`
  const lanLoginHint = `在运行本程序的电脑上打开 <code>${escapeHtml(panelUrl)}</code> 登录后可查看或重置；${passwordState.configured ? '密码由插件配置的 password 字段指定。' : `密码文件：<code>${escapeHtml(passwordState.file)}</code>`}`

  let server
  const actualPort = () => {
    const address = server?.address()
    return typeof address === 'object' && address !== null ? address.port : port
  }
  const accessLinks = () => lanIpv4Addresses().map(({ ip, label }) => ({
    ip,
    label,
    url: `http://${ip}:${String(actualPort())}/`,
  }))

  const ownerOnly = (req) => ctx.connection.requestRejection({ headers: req.headers, method: req.method })

  /** Owner-authenticated panel routes on the loopback server. */
  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: PANEL_PATH,
    handler: async (req, res) => {
      if (req.method === 'POST') {
        // The panel doubles as the local login form: enter the access password
        // and the browser receives a DSH session cookie for this origin.
        handlePasswordLogin(req, res, { redirectTo: PANEL_PATH, action: PANEL_PATH, hint: passwordRecoveryHint })
        return
      }
      const rejection = ownerOnly(req)
      if (rejection !== undefined) {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' })
        res.end(loginPage({ action: PANEL_PATH, hint: passwordRecoveryHint }))
        return
      }
      let resetNote = ''
      try {
        const reset = new URL(req.url ?? '/', 'http://placeholder').searchParams.get('reset')
        resetNote = reset === '1'
          ? '已更新访问密码；之前已登录设备的会话已失效，请用新密码重新登录。'
          : reset === 'error'
            ? '当前密码错误，密码未更改。'
            : reset === 'mismatch'
              ? '两次输入的新密码不一致，密码未更改。'
              : reset === 'short'
                ? '新密码需为 6–128 个字符，密码未更改。'
                : reset === 'invalid'
                  ? '新密码不符合要求，密码未更改。'
                  : ''
      } catch {
        /* keep the panel silent on a malformed query */
      }
      const body = renderPanel({
        bindHost,
        port: actualPort(),
        panelUrl,
        upstreamOrigin: upstream.href,
        links: accessLinks(),
        password: passwordState.password,
        passwordConfigured: passwordState.configured,
        resetNote,
      })
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' })
      res.end(req.method === 'HEAD' ? undefined : body)
    },
  }), 'dsh-lan-access: panel route')

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: PANEL_RESET_PATH,
    handler: (req, res) => {
      if (req.method !== 'POST') {
        res.writeHead(405, { 'content-type': 'text/plain; charset=utf-8', allow: 'POST' })
        res.end('POST only\n')
        return
      }
      if (passwordState.configured) {
        res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('密码由插件配置的 password 字段指定，修改请编辑插件配置。\n')
        return
      }
      // The reset action is gated by the current password itself (like a
      // website password change), not by the browser session cookie, so it
      // works in every browser, including the desktop app window.
      let body = ''
      req.setEncoding('utf8')
      req.on('data', (chunk) => {
        body += chunk
        if (body.length > MAX_LOGIN_BODY) req.destroy()
      })
      req.on('end', () => {
        if (lockedOut()) {
          res.writeHead(429, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
          res.end('尝试次数过多，请 1 分钟后再试。\n')
          return
        }
        const params = new URLSearchParams(body)
        const current = params.get('password') ?? ''
        if (!safeEqual(current, passwordState.password)) {
          failures.push(Date.now())
          res.writeHead(303, { location: `${PANEL_PATH}?reset=error`, 'cache-control': 'no-store' })
          res.end()
          return
        }
        failures.length = 0

        const mode = params.get('mode') ?? 'generate'
        let nextPassword
        if (mode === 'generate') {
          nextPassword = randomPassword()
        } else if (mode === 'set') {
          const candidate = params.get('newPassword') ?? ''
          const confirmation = params.get('confirmPassword') ?? ''
          if (candidate.length < 6 || candidate.length > 128) {
            res.writeHead(303, { location: `${PANEL_PATH}?reset=short`, 'cache-control': 'no-store' })
            res.end()
            return
          }
          if (candidate !== confirmation) {
            res.writeHead(303, { location: `${PANEL_PATH}?reset=mismatch`, 'cache-control': 'no-store' })
            res.end()
            return
          }
          nextPassword = candidate
        } else {
          res.writeHead(303, { location: `${PANEL_PATH}?reset=invalid`, 'cache-control': 'no-store' })
          res.end()
          return
        }

        try {
          passwordState.password = nextPassword
          passwordState.sessionCutoff = Date.now()
          writeFileSync(passwordState.file, `${JSON.stringify({ password: passwordState.password, sessionCutoff: passwordState.sessionCutoff }, null, 2)}\n`)
          ctx.logger.info(`dsh-lan-access: access password ${mode === 'set' ? 'changed to a custom value' : 'regenerated'} from the panel; previous device sessions revoked`)
        } catch (error) {
          ctx.logger.warn(`dsh-lan-access: cannot persist new password: ${error instanceof Error ? error.message : String(error)}`)
          res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
          res.end('failed to persist the new password\n')
          return
        }
        res.writeHead(303, { location: `${PANEL_PATH}?reset=1`, 'cache-control': 'no-store' })
        res.end()
      })
    },
  }), 'dsh-lan-access: panel reset route')

  /** Server-side launch-token exchange; the browser receives only the session cookie. */
  const performTokenExchange = () => {
    const target = new URL(ctx.connection.authenticatedUrl(upstream.href))
    return new Promise((resolve, reject) => {
      const requestImpl = target.protocol === 'https:' ? httpsRequest : httpRequest
      const req = requestImpl({
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port === '' ? undefined : target.port,
        path: `${target.pathname}${target.search}`,
        method: 'GET',
        headers: { host: target.host, accept: '*/*' },
        rejectUnauthorized: false,
      }, (res) => {
        const setCookies = res.headers['set-cookie'] ?? []
        res.resume()
        resolve({ status: res.statusCode ?? 0, setCookies })
      })
      req.on('error', reject)
      req.end()
    })
  }

  const lockedOut = () => {
    const cutoff = Date.now() - FAILURE_WINDOW_MS
    while (failures.length > 0 && failures[0] < cutoff) failures.shift()
    return failures.length >= FAILURE_LIMIT
  }

  const handlePasswordLogin = (req, res, { redirectTo, action, hint }) => {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'content-type': 'text/plain; charset=utf-8', allow: 'POST' })
      res.end('POST only\n')
      return
    }
    let body = ''
    req.setEncoding('utf8')
    req.on('data', (chunk) => {
      body += chunk
      if (body.length > MAX_LOGIN_BODY) req.destroy()
    })
    req.on('end', async () => {
      // This callback outlives the route handler, so an unhandled rejection
      // here would crash the Host process instead of failing one request.
      try {
        if (lockedOut()) {
          res.writeHead(429, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
          res.end(loginPage({ locked: true, action, hint }))
          return
        }
        const password = new URLSearchParams(body).get('password') ?? ''
        if (!safeEqual(password, passwordState.password)) {
          failures.push(Date.now())
          await delay(FAILURE_DELAY_MS)
          res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
          res.end(loginPage({ error: '密码错误，请重试。', action, hint }))
          return
        }
        failures.length = 0
        try {
          const exchange = await performTokenExchange()
          if (exchange.status !== 303 || exchange.setCookies.length === 0) {
            throw new Error(`unexpected exchange response ${exchange.status}`)
          }
          res.writeHead(303, {
            location: redirectTo,
            'cache-control': 'no-store',
            'referrer-policy': 'no-referrer',
            'set-cookie': exchange.setCookies,
          })
          res.end()
        } catch (error) {
          ctx.logger.warn(`dsh-lan-access: token exchange failed: ${error instanceof Error ? error.message : String(error)}`)
          res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
          res.end('登录服务暂不可用，请稍后重试。\n')
        }
      } catch (error) {
        ctx.logger.warn(`dsh-lan-access: login handler failed: ${error instanceof Error ? error.message : String(error)}`)
        try {
          if (!res.headersSent) {
            res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('internal error\n')
          } else {
            res.destroy()
          }
        } catch {
          res.destroy()
        }
      }
    })
  }

  // LAN reverse proxy listener.
  ctx.effect(async () => {
    const requestImpl = upstream.protocol === 'https:' ? httpsRequest : httpRequest
    const upstreamOptions = (req, headers) => ({
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstream.port === '' ? undefined : upstream.port,
      path: req.url,
      method: req.method,
      headers,
      rejectUnauthorized: false,
    })

    server = createServer((req, res) => {
      // A proxy listener must never let a socket or header error escape as an
      // uncaught exception: it would take the whole Host process down.
      res.on('error', () => {})
      try {
        let target
        try {
          target = new URL(req.url ?? '/', 'http://placeholder')
        } catch {
          target = new URL('/', 'http://placeholder')
        }
        const pathname = target.pathname

        if (pathname === LOGIN_PATH) {
          handlePasswordLogin(req, res, { redirectTo: '/', action: LOGIN_PATH, hint: lanLoginHint })
          return
        }
        if (isPanelPath(pathname)) {
          res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
          res.end('not found\n')
          return
        }
        // Launch-token URLs are not honored on the LAN port; password login replaces them.
        if (pathname === '/' && target.searchParams.has('token')) {
          res.writeHead(302, { location: '/', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' })
          res.end()
          return
        }

        const forwardedHeaders = rewriteOutgoingHeaders(req.headers, upstream)
        if (typeof forwardedHeaders.cookie === 'string') {
          forwardedHeaders.cookie = stripStaleCookies(forwardedHeaders.cookie, upstream.host, passwordState.sessionCutoff)
        }
        const proxy = requestImpl(upstreamOptions(req, forwardedHeaders), (upstreamRes) => {
          upstreamRes.on('error', () => res.destroy())
          if (upstreamRes.statusCode === 401 && req.method === 'GET' && (pathname === '/' || pathname === '')) {
            upstreamRes.resume()
            res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
            res.end(loginPage({ action: LOGIN_PATH, hint: lanLoginHint }))
            return
          }
          res.writeHead(upstreamRes.statusCode ?? 502, strippedHeaders(upstreamRes.headers))
          res.on('close', () => upstreamRes.destroy())
          upstreamRes.pipe(res)
        })
        proxy.on('error', (error) => {
          ctx.logger.warn(`dsh-lan-access: upstream error: ${error instanceof Error ? error.message : String(error)}`)
          if (!res.headersSent) {
            res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('bad gateway\n')
          } else {
            res.destroy()
          }
        })
        req.on('error', () => proxy.destroy())
        req.pipe(proxy)
      } catch (error) {
        ctx.logger.warn(`dsh-lan-access: request handler failed: ${error instanceof Error ? error.message : String(error)}`)
        if (res.headersSent) {
          res.destroy()
        } else {
          try {
            res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('internal error\n')
          } catch {
            res.destroy()
          }
        }
      }
    })

    server.on('upgrade', (req, socket, head) => {
      // Upgraded sockets leave the server's own error handling; without this
      // a client reset (ECONNRESET) becomes an uncaught exception.
      socket.on('error', () => socket.destroy())
      try {
        const pathname = requestPathname(req)
        if (isPanelPath(pathname) || pathname === LOGIN_PATH) {
          socket.destroy()
          return
        }
        const forwardedHeaders = upgradeHeaders(req.headers, upstream)
        if (typeof forwardedHeaders.cookie === 'string') {
          forwardedHeaders.cookie = stripStaleCookies(forwardedHeaders.cookie, upstream.host, passwordState.sessionCutoff)
        }
        const proxy = requestImpl(upstreamOptions(req, forwardedHeaders))
        proxy.on('error', () => socket.destroy())
        // Upstream refused the upgrade with a plain HTTP response (for example
        // 401 for a revoked session): relay it so the client fails cleanly
        // instead of hanging on a dead socket.
        proxy.on('response', (res) => {
          res.on('error', () => socket.destroy())
          socket.on('close', () => res.destroy())
          if (socket.destroyed) {
            res.destroy()
            return
          }
          const lines = [`HTTP/1.1 ${res.statusCode ?? 502} ${res.statusMessage ?? ''}`]
          for (let i = 0; i < res.rawHeaders.length; i += 2) {
            lines.push(`${res.rawHeaders[i]}: ${res.rawHeaders[i + 1]}`)
          }
          lines.push('', '')
          socket.write(lines.join('\r\n'))
          res.on('data', (chunk) => {
            if (!socket.destroyed) socket.write(chunk)
          })
          res.on('end', () => {
            if (!socket.destroyed) socket.end()
          })
        })
        proxy.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
          upstreamSocket.on('error', () => socket.destroy())
          socket.on('close', () => upstreamSocket.destroy())
          upstreamSocket.on('close', () => socket.destroy())
          if (socket.destroyed) {
            upstreamSocket.destroy()
            return
          }
          const lines = [`HTTP/1.1 ${upstreamRes.statusCode ?? 502} ${upstreamRes.statusMessage ?? ''}`]
          for (let i = 0; i < upstreamRes.rawHeaders.length; i += 2) {
            lines.push(`${upstreamRes.rawHeaders[i]}: ${upstreamRes.rawHeaders[i + 1]}`)
          }
          lines.push('', '')
          socket.write(lines.join('\r\n'))
          if (upstreamHead && upstreamHead.length > 0) upstreamSocket.unshift(upstreamHead)
          socket.pipe(upstreamSocket)
          upstreamSocket.pipe(socket)
        })
        proxy.end()
      } catch (error) {
        ctx.logger.warn(`dsh-lan-access: upgrade handler failed: ${error instanceof Error ? error.message : String(error)}`)
        socket.destroy()
      }
    })
    server.on('clientError', (error, socket) => {
      ctx.logger.warn(`dsh-lan-access: client error: ${error?.message ?? String(error)}`)
      if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
    })
    // Blanket guard for every accepted socket: an unhandled socket error on
    // this listener must never crash the Host process.
    server.on('connection', (socket) => {
      socket.on('error', () => socket.destroy())
    })

    await new Promise((resolve, reject) => {
      const onError = (error) => {
        server.off('listening', onListening)
        reject(error)
      }
      const onListening = () => {
        server.off('error', onError)
        resolve()
      }
      server.once('error', onError)
      server.once('listening', onListening)
      server.listen(port, bindHost)
    })
    server.on('error', (error) => {
      ctx.logger.warn(`dsh-lan-access: listener error: ${error?.message ?? String(error)}`)
    })

    const boundPort = actualPort()
    ctx.logger.info(`dsh-lan-access: LAN proxy listening on http://${bindHost}:${String(boundPort)} -> ${upstream.href}`)
    ctx.logger.info(`dsh-lan-access: access panel at ${panelUrl}`)

    return () => new Promise((resolve) => {
      server.closeAllConnections?.()
      server.close(() => resolve())
    })
  }, 'dsh-lan-access: LAN listener')
}

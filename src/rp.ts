/**
 * Mock OIDC RP(Relying Party / 客户端)。
 * 让你把本 mock 当成一个"客户端",去连接任意 **外部 OP / IdP**(如 Keycloak、
 * Auth0、Okta、Azure AD,或本站自己的 Mock OP),完整走一遍 Authorization Code
 * + PKCE 登录,并展示每一步:Discovery、授权跳转、令牌交换、ID Token 验签、UserInfo。
 *
 * 端点:
 *   GET  /rp/            —— 配置表单(外部 OP issuer、client_id 等)
 *   GET  /rp/start       —— 拉取 Discovery、发起登录(重定向到外部 OP)
 *   GET  /rp/callback    —— 接收回调,换取并验证令牌,展示结果
 *
 * 无状态:登录上下文(PKCE verifier、nonce、各端点)打包成签名 JWT 存入
 * HttpOnly cookie,回调时取回。仅供测试。
 */
import { signJwt, verifyJwt, s256, b64urlDecode } from './jwt'

const COOKIE = 'authn_rp_ctx'

function html(body: string, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(
    `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mock OIDC RP</title>
<style>
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;max-width:760px;margin:2.5rem auto;padding:0 1.2rem;color:#2c3e50;line-height:1.7}
code,pre{font-family:ui-monospace,monospace;background:#f6f8fa;border-radius:4px}
code{padding:.15rem .4rem;font-size:.88em}
pre{padding:.8rem;overflow-x:auto;font-size:.8rem;white-space:pre-wrap;word-break:break-all}
label{display:block;font-weight:600;margin:.8rem 0 .3rem}
input{width:100%;box-sizing:border-box;padding:.5rem .6rem;border:1px solid #dcdfe6;border-radius:6px;font-size:.9rem}
.btn{display:inline-block;margin-top:1rem;padding:.6rem 1.4rem;background:#3eaf7c;color:#fff;border:none;border-radius:6px;font-size:.95rem;cursor:pointer;text-decoration:none}
.warn{background:#fff3cd;border-left:4px solid #e0a800;padding:.7rem 1rem;border-radius:4px;font-size:.9rem}
.ok{color:#2e7d32;font-weight:600}.bad{color:#e53935;font-weight:600}
h2{font-size:1.15rem;margin-top:1.8rem}
</style></head><body>${body}</body></html>`,
    { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders } },
  )
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

// --------------------------------------------------------------------------
// 配置表单
// --------------------------------------------------------------------------

export function rpHome(issuer: string): Response {
  const selfOp = issuer // 默认连本站自己的 Mock OP,方便一键体验
  return html(`
<h1>🔌 Mock OIDC RP(客户端)</h1>
<p>用本工具作为一个 OIDC 客户端,连接 <strong>任意外部 OP / IdP</strong>,完整走一遍
Authorization Code + PKCE 登录并展示每一步。默认已填好本站的
<a href="${esc(selfOp)}/.well-known/openid-configuration" target="_blank">Mock OP</a>,可直接体验;
也可换成 Keycloak / Auth0 / Okta / Azure AD 等。</p>
<form method="GET" action="/rp/start">
  <label>外部 OP 的 Issuer 或 Discovery URL</label>
  <input name="op" value="${esc(selfOp)}" placeholder="https://your-op.example 或 .../.well-known/openid-configuration"/>
  <label>client_id</label>
  <input name="client_id" value="authn-mock-rp" placeholder="你在该 OP 注册的 client_id"/>
  <label>client_secret（可选,公共客户端留空,仅用 PKCE）</label>
  <input name="client_secret" value="" placeholder="留空表示 public client（推荐,PKCE）"/>
  <label>scope</label>
  <input name="scope" value="openid profile email"/>
  <button class="btn" type="submit">发起登录</button>
</form>
<p class="warn">提示:请在你的外部 OP 上,把回调地址
<code>${esc(issuer)}/rp/callback</code> 加入该 client 的 redirect_uri 白名单。
client_secret(若填)会存入你浏览器的 HttpOnly cookie 用于本次令牌交换,不会发往除该 OP 外的任何地方。</p>
`)
}

// --------------------------------------------------------------------------
// 发起登录
// --------------------------------------------------------------------------

interface Discovery {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  userinfo_endpoint?: string
}

async function fetchDiscovery(op: string): Promise<Discovery> {
  const url = op.includes('/.well-known/openid-configuration')
    ? op
    : op.replace(/\/$/, '') + '/.well-known/openid-configuration'
  const res = await fetch(url, { headers: { Accept: 'application/json' } })
  if (!res.ok) throw new Error(`拉取 Discovery 失败(${res.status}):${url}`)
  const doc = (await res.json()) as Discovery
  if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new Error('Discovery 文档缺少必要端点(authorization_endpoint/token_endpoint/jwks_uri)')
  }
  return doc
}

function randStr(n = 32): string {
  const bytes = crypto.getRandomValues(new Uint8Array(n))
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function rpStart(req: Request, issuer: string): Promise<Response> {
  const q = new URL(req.url).searchParams
  const op = q.get('op')?.trim()
  const clientId = q.get('client_id')?.trim()
  const clientSecret = q.get('client_secret')?.trim() || undefined
  const scope = q.get('scope')?.trim() || 'openid profile email'
  if (!op || !clientId) return html('<p class="bad">缺少 op 或 client_id。</p><p><a href="/rp/">返回</a></p>', 400)

  let disco: Discovery
  try {
    disco = await fetchDiscovery(op)
  } catch (e) {
    return html(`<p class="bad">${esc((e as Error).message)}</p><p><a href="/rp/">返回</a></p>`, 502)
  }

  const verifier = randStr(32)
  const state = randStr(16)
  const nonce = randStr(16)
  const redirectUri = `${issuer}/rp/callback`

  const ctx = await signJwt({
    token_use: 'rp_ctx',
    verifier,
    state,
    nonce,
    client_id: clientId,
    client_secret: clientSecret,
    issuer: disco.issuer,
    authorization_endpoint: disco.authorization_endpoint,
    token_endpoint: disco.token_endpoint,
    jwks_uri: disco.jwks_uri,
    userinfo_endpoint: disco.userinfo_endpoint,
    redirect_uri: redirectUri,
    exp: Math.floor(Date.now() / 1000) + 600,
  })

  const authz = new URL(disco.authorization_endpoint)
  authz.searchParams.set('response_type', 'code')
  authz.searchParams.set('client_id', clientId)
  authz.searchParams.set('redirect_uri', redirectUri)
  authz.searchParams.set('scope', scope)
  authz.searchParams.set('state', state)
  authz.searchParams.set('nonce', nonce)
  authz.searchParams.set('code_challenge', await s256(verifier))
  authz.searchParams.set('code_challenge_method', 'S256')

  return new Response(null, {
    status: 302,
    headers: {
      Location: authz.toString(),
      'Set-Cookie': `${COOKIE}=${ctx}; HttpOnly; Secure; SameSite=Lax; Path=/rp; Max-Age=600`,
      'Cache-Control': 'no-store',
    },
  })
}

// --------------------------------------------------------------------------
// 回调:换取并验证令牌
// --------------------------------------------------------------------------

function readCookie(req: Request, name: string): string | null {
  const header = req.headers.get('Cookie')
  if (!header) return null
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k === name) return v.join('=')
  }
  return null
}

function decodeJwtPart(seg: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(b64urlDecode(seg)))
}

async function verifyExternalIdToken(
  idToken: string,
  jwksUri: string,
): Promise<{ ok: boolean; reason?: string; payload?: Record<string, unknown> }> {
  const parts = idToken.split('.')
  if (parts.length !== 3) return { ok: false, reason: 'ID Token 格式错误' }
  const header = decodeJwtPart(parts[0])
  if (header.alg !== 'RS256') {
    return { ok: false, reason: `暂只支持 RS256 验签,收到 alg=${String(header.alg)}` }
  }
  let keys: Array<Record<string, unknown>>
  try {
    const res = await fetch(jwksUri, { headers: { Accept: 'application/json' } })
    keys = ((await res.json()) as { keys: Array<Record<string, unknown>> }).keys
  } catch {
    return { ok: false, reason: '拉取 JWKS 失败' }
  }
  const jwk =
    keys.find((k) => k.kid === header.kid && k.kty === 'RSA') ??
    keys.find((k) => k.kty === 'RSA')
  if (!jwk) return { ok: false, reason: 'JWKS 中找不到匹配的 RSA 公钥' }
  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'RSA', n: jwk.n as string, e: jwk.e as string, alg: 'RS256' },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  )
  const valid = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    b64urlDecode(parts[2]),
    new TextEncoder().encode(parts[0] + '.' + parts[1]),
  )
  if (!valid) return { ok: false, reason: '签名验证失败' }
  return { ok: true, payload: decodeJwtPart(parts[1]) }
}

export async function rpCallback(req: Request): Promise<Response> {
  const q = new URL(req.url).searchParams
  const error = q.get('error')
  if (error) {
    return html(`<h1>登录失败</h1><p class="bad">${esc(error)} — ${esc(q.get('error_description') ?? '')}</p><p><a href="/rp/">重试</a></p>`)
  }
  const code = q.get('code')
  const state = q.get('state')
  const ctxRaw = readCookie(req, COOKIE)
  if (!code || !ctxRaw) {
    return html('<p class="bad">缺少 code 或登录上下文 cookie(可能已过期)。</p><p><a href="/rp/">重试</a></p>', 400)
  }
  const ctx = await verifyJwt(ctxRaw)
  if (!ctx || ctx.token_use !== 'rp_ctx') {
    return html('<p class="bad">登录上下文无效或已过期。</p><p><a href="/rp/">重试</a></p>', 400)
  }
  if (state !== ctx.state) {
    return html('<p class="bad">state 不匹配,已中止(防 CSRF)。</p><p><a href="/rp/">重试</a></p>', 400)
  }

  // 令牌交换
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: String(ctx.redirect_uri),
    client_id: String(ctx.client_id),
    code_verifier: String(ctx.verifier),
  })
  if (ctx.client_secret) body.set('client_secret', String(ctx.client_secret))
  const tokenRes = await fetch(String(ctx.token_endpoint), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body,
  })
  const tokens = (await tokenRes.json()) as Record<string, unknown>
  if (!tokenRes.ok) {
    return html(
      `<h1>令牌交换失败</h1><pre>${esc(JSON.stringify(tokens, null, 2))}</pre><p><a href="/rp/">重试</a></p>`,
      502,
    )
  }

  // 验证 ID Token
  let verifyBlock = '<p class="bad">响应中没有 id_token(该 OP 可能未按 OIDC 返回,或 scope 未含 openid)。</p>'
  let idPayload: Record<string, unknown> | undefined
  if (typeof tokens.id_token === 'string') {
    const v = await verifyExternalIdToken(tokens.id_token, String(ctx.jwks_uri))
    idPayload = v.payload
    const checks: string[] = []
    checks.push(v.ok ? '✔ 签名验证通过(JWKS)' : `✗ 签名验证失败:${v.reason}`)
    if (v.payload) {
      checks.push(
        v.payload.iss === ctx.issuer ? '✔ iss 匹配' : `✗ iss 不匹配(期望 ${esc(String(ctx.issuer))})`,
      )
      const aud = v.payload.aud
      const audOk = aud === ctx.client_id || (Array.isArray(aud) && aud.includes(ctx.client_id))
      checks.push(audOk ? '✔ aud 匹配' : '✗ aud 不匹配')
      checks.push(
        v.payload.nonce === ctx.nonce ? '✔ nonce 匹配' : '✗ nonce 不匹配',
      )
      const exp = typeof v.payload.exp === 'number' ? v.payload.exp : 0
      checks.push(exp > Math.floor(Date.now() / 1000) ? '✔ 未过期' : '✗ 已过期')
    }
    verifyBlock =
      `<p>${checks.map((c) => (c.startsWith('✔') ? `<span class="ok">${c}</span>` : `<span class="bad">${c}</span>`)).join('<br>')}</p>` +
      (idPayload ? `<h2>解码后的 ID Token</h2><pre>${esc(JSON.stringify(idPayload, null, 2))}</pre>` : '')
  }

  // UserInfo
  let userinfoBlock = ''
  if (ctx.userinfo_endpoint && typeof tokens.access_token === 'string') {
    try {
      const uiRes = await fetch(String(ctx.userinfo_endpoint), {
        headers: { Authorization: 'Bearer ' + tokens.access_token, Accept: 'application/json' },
      })
      const ui = await uiRes.json()
      userinfoBlock = `<h2>UserInfo 端点响应</h2><pre>${esc(JSON.stringify(ui, null, 2))}</pre>`
    } catch {
      userinfoBlock = '<h2>UserInfo</h2><p class="bad">调用 UserInfo 失败。</p>'
    }
  }

  const shown = { ...tokens }
  for (const k of ['access_token', 'id_token', 'refresh_token']) {
    if (typeof shown[k] === 'string') shown[k] = (shown[k] as string).slice(0, 32) + '…'
  }

  return html(
    `<h1 class="ok">✔ 登录成功</h1>
<p>已作为客户端 <code>${esc(String(ctx.client_id))}</code> 从 OP <code>${esc(String(ctx.issuer))}</code> 完成登录。</p>
<h2>Token 端点响应</h2><pre>${esc(JSON.stringify(shown, null, 2))}</pre>
<h2>ID Token 验证</h2>${verifyBlock}
${userinfoBlock}
<p><a class="btn" href="/rp/">再试一次</a></p>`,
    200,
    { 'Set-Cookie': `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/rp; Max-Age=0` },
  )
}

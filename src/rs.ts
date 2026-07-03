/**
 * Mock OIDC / OAuth2 资源服务器(Resource Server)。
 * 演示 OAuth2 中 RP 之外的另一角色:一个受 Bearer access token 保护的 API。
 * 校验本站 Mock OP 签发的 access token(签名、过期、token_use、scope),
 * 通过后返回"受保护资源"。
 *
 * 端点:
 *   GET /rs/       —— 说明页与调用示例
 *   GET /rs/api    —— 受保护 API(需 Authorization: Bearer <access_token>)
 */
import { verifyJwt } from './jwt'

const REQUIRED_SCOPE = 'profile'

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      ...headers,
    },
  })
}

export async function rsApi(req: Request): Promise<Response> {
  const auth = req.headers.get('Authorization')
  if (!auth?.startsWith('Bearer ')) {
    return json(
      { error: 'invalid_request', error_description: '缺少 Bearer access token' },
      401,
      { 'WWW-Authenticate': 'Bearer' },
    )
  }
  const token = auth.slice(7)
  const claims = await verifyJwt(token)
  if (!claims || claims.token_use !== 'access') {
    return json(
      { error: 'invalid_token', error_description: 'access token 无效或已过期' },
      401,
      { 'WWW-Authenticate': 'Bearer error="invalid_token"' },
    )
  }
  const scopes = String(claims.scope ?? '').split(/\s+/).filter(Boolean)
  if (!scopes.includes(REQUIRED_SCOPE)) {
    return json(
      {
        error: 'insufficient_scope',
        error_description: `该资源需要 scope "${REQUIRED_SCOPE}",当前令牌 scope:${scopes.join(' ') || '(无)'}`,
        required_scope: REQUIRED_SCOPE,
      },
      403,
      { 'WWW-Authenticate': `Bearer error="insufficient_scope", scope="${REQUIRED_SCOPE}"` },
    )
  }
  return json({
    message: '✔ 访问受保护资源成功',
    resource: 'https://mock-resource.example/profile',
    authorized_subject: claims.sub,
    client_id: claims.client_id,
    granted_scope: scopes,
    token_expires_at: claims.exp,
    data: {
      note: '这是一份 mock 受保护资源。资源服务器仅信任由本站 Mock OP 签名、未过期且含所需 scope 的 access token。',
    },
  })
}

export function rsHome(issuer: string): Response {
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  return new Response(
    `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Mock 资源服务器</title>
<style>
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;max-width:760px;margin:2.5rem auto;padding:0 1.2rem;color:#2c3e50;line-height:1.7}
code,pre{font-family:ui-monospace,monospace;background:#f6f8fa;border-radius:4px}
code{padding:.15rem .4rem;font-size:.88em}
pre{padding:.8rem;overflow-x:auto;font-size:.82rem;white-space:pre-wrap;word-break:break-all}
.warn{background:#fff3cd;border-left:4px solid #e0a800;padding:.7rem 1rem;border-radius:4px;font-size:.9rem}
h2{font-size:1.15rem;margin-top:1.8rem}
</style></head><body>
<h1>🔒 Mock 资源服务器(Resource Server)</h1>
<p>OAuth2 里 RP(客户端)之外的另一角色:一个受 Bearer access token 保护的 API。
它只信任本站 <a href="${esc(issuer)}/.well-known/openid-configuration" target="_blank">Mock OP</a>
签发、<strong>未过期</strong>且 <strong>scope 含 <code>profile</code></strong> 的 access token。</p>

<h2>受保护端点</h2>
<p><code>GET ${esc(issuer)}/rs/api</code> — 需请求头 <code>Authorization: Bearer &lt;access_token&gt;</code></p>

<h2>试用步骤</h2>
<p>1) 先从 Mock OP 拿一个 access token(用授权码流程,或最简单的 client_credentials):</p>
<pre>curl -s -X POST ${esc(issuer)}/oidc/token \\
  -d grant_type=client_credentials -d client_id=demo -d scope="openid profile"</pre>
<p>2) 用返回的 <code>access_token</code> 调用受保护 API:</p>
<pre>curl -s ${esc(issuer)}/rs/api -H "Authorization: Bearer &lt;access_token&gt;"</pre>
<p>令牌有效、scope 足够 → 返回受保护资源;缺 scope → <code>403 insufficient_scope</code>;
无/失效令牌 → <code>401 invalid_token</code>。</p>
<p class="warn">仅供测试。真实资源服务器还应校验 <code>aud</code>/<code>iss</code>,并按最小权限设计 scope。</p>
</body></html>`,
    { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } },
  )
}

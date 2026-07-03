const STYLE = `
  body { font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         max-width: 720px; margin: 3rem auto; padding: 0 1.2rem; line-height: 1.7; color: #2c3e50; }
  h1 { font-size: 1.6rem; } h2 { font-size: 1.2rem; margin-top: 2rem; }
  code, pre { font-family: ui-monospace, monospace; background: #f6f8fa; border-radius: 4px; }
  code { padding: 0.15rem 0.4rem; font-size: 0.88em; }
  pre { padding: 0.9rem; overflow-x: auto; font-size: 0.82rem; }
  .warn { background: #fff3cd; border-left: 4px solid #e0a800; padding: 0.7rem 1rem; border-radius: 4px; }
  .user-btn { display: block; margin: 0.6rem 0; padding: 0.8rem 1.2rem; border: 1px solid #3eaf7c;
              border-radius: 8px; text-decoration: none; color: #2c3e50; }
  .user-btn:hover { background: #f0faf5; }
  .user-btn strong { color: #3eaf7c; }
  table { border-collapse: collapse; width: 100%; font-size: 0.9rem; }
  th, td { border: 1px solid #dfe2e5; padding: 0.4rem 0.8rem; text-align: left; }
  a { color: #3eaf7c; }
`

export function homePage(issuer: string): string {
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authn Mock — OIDC OP</title><style>${STYLE}</style></head>
<body>
<h1>🧪 Authn Mock OIDC Provider</h1>
<p class="warn"><strong>仅供开发与测试。</strong>签名私钥公开在源码中,任何人都可伪造本服务签发的令牌。生产系统绝不能信任此服务。</p>

<h2>端点</h2>
<table>
<tr><th>Discovery</th><td><a href="${issuer}/.well-known/openid-configuration"><code>${issuer}/.well-known/openid-configuration</code></a></td></tr>
<tr><th>Authorize</th><td><code>${issuer}/oidc/authorize</code></td></tr>
<tr><th>Token</th><td><code>${issuer}/oidc/token</code></td></tr>
<tr><th>UserInfo</th><td><code>${issuer}/oidc/userinfo</code></td></tr>
<tr><th>JWKS</th><td><a href="${issuer}/oidc/jwks.json"><code>${issuer}/oidc/jwks.json</code></a></td></tr>
</table>

<h2>测试用户</h2>
<table>
<tr><th>user 参数</th><th>sub</th><th>email</th></tr>
<tr><td><code>alice</code></td><td><code>mock-user-alice</code></td><td>alice@mock.authn.example（已验证）</td></tr>
<tr><td><code>bob</code></td><td><code>mock-user-bob</code></td><td>bob@mock.authn.example（未验证）</td></tr>
</table>

<h2>快速开始</h2>
<p>任意 <code>client_id</code> / <code>redirect_uri</code> 均被接受,无需注册。浏览器访问:</p>
<pre>${issuer}/oidc/authorize?client_id=demo&redirect_uri=https://your-app.example/callback&response_type=code&scope=openid+profile+email&state=xyz&nonce=n-abc</pre>
<p>选择测试用户后携带 <code>code</code> 回跳。免交互(CI 场景)可直接加 <code>&user=alice</code>。然后换取令牌:</p>
<pre>curl -X POST ${issuer}/oidc/token \\
  -d grant_type=authorization_code \\
  -d code=&lt;code&gt; \\
  -d redirect_uri=https://your-app.example/callback \\
  -d client_id=demo</pre>

<p>特性:PKCE(S256)、refresh_token(<code>scope</code> 含 <code>offline_access</code> 时签发)、client_credentials、CORS 全开。
文档与协议讲解见 <a href="https://authn-cn.github.io/">authn-cn.github.io</a>。</p>
</body></html>`
}

export function loginPage(params: URLSearchParams): string {
  const mk = (user: string): string => {
    const q = new URLSearchParams(params)
    q.set('user', user)
    return `/oidc/authorize?${q.toString()}`
  }
  const esc = (s: string | null): string =>
    (s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;')
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>选择测试用户 — Authn Mock</title><style>${STYLE}</style></head>
<body>
<h1>选择一个测试用户登录</h1>
<p>客户端 <code>${esc(params.get('client_id'))}</code> 请求登录,scope:<code>${esc(params.get('scope'))}</code></p>
<a class="user-btn" href="${mk('alice')}"><strong>Alice Zhang</strong>（alice@mock.authn.example,email 已验证）</a>
<a class="user-btn" href="${mk('bob')}"><strong>Bob Li</strong>（bob@mock.authn.example,email 未验证）</a>
<p class="warn">这是 Mock IdP,没有密码——点谁就是谁。仅供测试。</p>
</body></html>`
}

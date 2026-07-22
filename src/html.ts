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
<h1>🧪 Authn Mock 认证服务</h1>
<p class="warn"><strong>仅供开发与测试。</strong>签名私钥/证书公开在源码中,任何人都可伪造本服务签发的令牌或断言。生产系统绝不能信任此服务。</p>

<p>提供三类 mock 角色:<strong>OIDC OP</strong>(身份提供方)、<strong>SAML IdP</strong>(身份提供方)、<strong>OIDC RP</strong>(客户端,可连接任意外部 OP)。</p>

<h2>OIDC OP 端点</h2>
<table>
<tr><th>Discovery</th><td><a href="${issuer}/.well-known/openid-configuration"><code>${issuer}/.well-known/openid-configuration</code></a></td></tr>
<tr><th>Authorize</th><td><code>${issuer}/oidc/authorize</code></td></tr>
<tr><th>Token</th><td><code>${issuer}/oidc/token</code></td></tr>
<tr><th>UserInfo</th><td><code>${issuer}/oidc/userinfo</code></td></tr>
<tr><th>JWKS</th><td><a href="${issuer}/oidc/jwks.json"><code>${issuer}/oidc/jwks.json</code></a></td></tr>
</table>

<h2>SAML IdP 端点</h2>
<table>
<tr><th>Metadata</th><td><a href="${issuer}/saml/idp/metadata"><code>${issuer}/saml/idp/metadata</code></a></td></tr>
<tr><th>SSO（Redirect/POST）</th><td><code>${issuer}/saml/idp/sso</code></td></tr>
</table>
<p>把上面的 Metadata URL 导入你的 SP 即可对接。SP-initiated 直接向 SSO 端点发 AuthnRequest;
IdP-initiated 可访问 <code>${issuer}/saml/idp/sso?user=alice&amp;sp=&lt;SP-entityID&gt;&amp;acs=&lt;SP-ACS-URL&gt;</code>。</p>

<h2>SAML SP（服务提供方）</h2>
<p><a href="${issuer}/saml/sp/">打开 SP 控制台 →</a> 作为 SP 与 IdP 配对完成 Web Browser SSO。默认对接本站
Mock IdP,可一键端到端演示;ACS 会展示验签与断言解析结果。Metadata:
<a href="${issuer}/saml/sp/metadata"><code>${issuer}/saml/sp/metadata</code></a></p>

<h2>OIDC RP（客户端）</h2>
<p><a href="${issuer}/rp/">打开 RP 控制台 →</a> 用本 mock 作为客户端,连接任意外部 OP / IdP(Keycloak、Auth0、Okta、Azure AD 或本站 Mock OP),
完整走一遍登录并展示 Discovery、令牌、ID Token 验签与 UserInfo。</p>

<h2>资源服务器（Resource Server）</h2>
<p><a href="${issuer}/rs/">打开资源服务器说明 →</a> 一个受 Bearer access token 保护的 API(<code>${issuer}/rs/api</code>),
演示 OAuth2 里 RP 之外的角色:校验令牌签名、过期与 scope 后返回受保护资源。</p>

<h2>TOTP 验证器（第二因素）</h2>
<p><a href="${issuer}/totp/">打开 TOTP 说明 →</a> 按 Base32 密钥计算当前验证码(<code>/totp/code</code>,充当认证器)或校验验证码(<code>/totp/verify</code>,带时间容错)。RFC 4226 / 6238。</p>

<h2>WebAuthn RP（Passkey）</h2>
<p><a href="${issuer}/webauthn/">打开 WebAuthn 演示 →</a> 自包含的依赖方:在浏览器里完整跑通 Passkey 注册与登录,服务端真实解析 attestation 并用注册公钥验证登录断言签名。</p>

<h2>邮件服务器(收件箱)</h2>
<p><a href="${issuer}/mail/">打开 Mock 收件箱 →</a> 用 Cloudflare Email Routing 接收邮件,在线或用 API 查看,并自动抽取一次性验证码。
联调邮件 OTP:发验证码到某地址后,<code>GET ${issuer}/mail/api/latest?to=&lt;地址&gt;</code> 即可取回;无需真实收信可
<code>POST ${issuer}/mail/api/inject</code> 注入假邮件。</p>

<h2>微信扫码登录（Mock 微信开放平台）</h2>
<p><a href="${issuer}/wechat/">打开 Mock 微信登录 →</a> 与微信开放平台"网站应用"扫码登录 <strong>输入输出完全一致,只是域名不同</strong>:同名 <code>WxLogin</code> JS SDK、相同回跳 <code>redirect_uri?code=&amp;state=</code>、相同的 <code>/sns/oauth2/access_token</code> 与 <code>/sns/userinfo</code> 接口字段。扫码也跳转到本站,确认后返回固定测试用户。</p>

<h2>企业微信扫码登录（Mock WeCom）</h2>
<p><a href="${issuer}/wecom/">打开 Mock 企业微信登录 →</a> 与企业微信官方网页扫码登录 <strong>输入输出一致</strong>:同名 <code>WwLogin</code> SDK、相同回跳 <code>redirect_uri?code=&amp;state=</code>、按企业微信规范分三步取用户信息(<code>gettoken</code> → <code>auth/getuserinfo</code> → <code>user/get</code>)。所有端点收敛在 <code>${issuer}/wecom</code> 下。扫码也跳转到本站,确认后返回固定测试成员。</p>

<h2>LDAP 目录(搜索模拟器)</h2>
<p><a href="${issuer}/ldap/">打开 Mock LDAP 说明 →</a> 用 HTTP/JSON 暴露固定示例目录并按 RFC 4515 过滤器求值(非真 LDAP 协议;Workers 无法监听 TCP)。
搜索:<code>${issuer}/ldap/search?base=&amp;scope=&amp;filter=</code>。</p>

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
文档与协议讲解见 <a href="https://authn-cn.pages.dev/">authn-cn.pages.dev</a>。</p>
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

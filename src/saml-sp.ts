/**
 * Mock SAML 2.0 SP(服务提供方)。
 * 与本站 Mock SAML IdP 配对,可端到端演示 SAML Web Browser SSO;也可对接外部 IdP。
 *
 * 端点:
 *   GET  /saml/sp/metadata  —— SP Metadata(SPSSODescriptor、ACS 端点)
 *   GET  /saml/sp/login     —— SP-initiated:构造 AuthnRequest 并重定向到 IdP SSO
 *   POST /saml/sp/acs       —— Assertion Consumer Service:接收并验证 IdP 的 Response
 *
 * 对本站 IdP 签发的 Response 会自动验签(同一密钥);外部 IdP 的 Response 会展示
 * 解析结果并说明需 IdP 证书才能验签。仅供测试。
 */
import { el, t, verifyEnveloped } from './xmldsig'

const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion'
const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol'
const NF_EMAIL = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
const B_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
const B_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'

function spEntityId(issuer: string): string {
  return `${issuer}/saml/sp/metadata`
}
function acsUrl(issuer: string): string {
  return `${issuer}/saml/sp/acs`
}
function idpEntityId(issuer: string): string {
  return `${issuer}/saml/idp/metadata`
}
function isoNoMs(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z')
}
function newId(): string {
  return '_' + crypto.randomUUID().replace(/-/g, '')
}

function page(body: string, status = 200): Response {
  return new Response(
    `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Mock SAML SP</title>
<style>
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;max-width:760px;margin:2.5rem auto;padding:0 1.2rem;color:#2c3e50;line-height:1.7}
code,pre{font-family:ui-monospace,monospace;background:#f6f8fa;border-radius:4px}
code{padding:.15rem .4rem;font-size:.88em}
pre{padding:.8rem;overflow-x:auto;font-size:.78rem;white-space:pre-wrap;word-break:break-all}
label{display:block;font-weight:600;margin:.8rem 0 .3rem}
input{width:100%;box-sizing:border-box;padding:.5rem .6rem;border:1px solid #dcdfe6;border-radius:6px;font-size:.9rem}
.btn{display:inline-block;margin-top:1rem;padding:.6rem 1.4rem;background:#3eaf7c;color:#fff;border:none;border-radius:6px;font-size:.95rem;cursor:pointer;text-decoration:none}
.warn{background:#fff3cd;border-left:4px solid #e0a800;padding:.7rem 1rem;border-radius:4px;font-size:.9rem}
.ok{color:#2e7d32;font-weight:600}.bad{color:#e53935;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border:1px solid #dfe2e5;padding:.4rem .8rem;text-align:left}
h2{font-size:1.15rem;margin-top:1.8rem}
</style></head><body>${body}</body></html>`,
    { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } },
  )
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

// --------------------------------------------------------------------------
// Metadata
// --------------------------------------------------------------------------

export function spMetadata(issuer: string): Response {
  const xml =
    '<?xml version="1.0" encoding="UTF-8"?>' +
    el(
      'md:EntityDescriptor',
      { 'xmlns:md': NS_MD, entityID: spEntityId(issuer) },
      el(
        'md:SPSSODescriptor',
        { AuthnRequestsSigned: 'false', WantAssertionsSigned: 'true', protocolSupportEnumeration: NS_SAMLP },
        el('md:NameIDFormat', {}, t(NF_EMAIL)) +
          el('md:AssertionConsumerService', {
            Binding: B_POST,
            Location: acsUrl(issuer),
            index: '0',
            isDefault: 'true',
          }),
      ),
    )
  return new Response(xml, {
    headers: {
      'Content-Type': 'application/samlmetadata+xml; charset=utf-8',
      'Content-Disposition': 'inline; filename="authn-mock-sp-metadata.xml"',
    },
  })
}

// --------------------------------------------------------------------------
// SP-initiated login
// --------------------------------------------------------------------------

async function deflateRaw(text: string): Promise<Uint8Array> {
  const cs = new CompressionStream('deflate-raw')
  const stream = new Blob([new TextEncoder().encode(text)]).stream().pipeThrough(cs)
  return new Uint8Array(await new Response(stream).arrayBuffer())
}
function bytesToB64(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

export async function spLogin(req: Request, issuer: string): Promise<Response> {
  const q = new URL(req.url).searchParams
  const idpSso = q.get('idp_sso')?.trim() || `${issuer}/saml/idp/sso`
  const relayState = q.get('relay')?.trim() || `${issuer}/saml/sp/acs`

  const authnRequest = el(
    'samlp:AuthnRequest',
    {
      'xmlns:samlp': NS_SAMLP,
      'xmlns:saml': NS_SAML,
      AssertionConsumerServiceURL: acsUrl(issuer),
      Destination: idpSso,
      ID: newId(),
      IssueInstant: isoNoMs(new Date()),
      ProtocolBinding: B_POST,
      Version: '2.0',
    },
    el('saml:Issuer', {}, t(spEntityId(issuer))) +
      el('samlp:NameIDPolicy', { AllowCreate: 'true', Format: NF_EMAIL }),
  )
  const encoded = bytesToB64(await deflateRaw(authnRequest))
  const location = new URL(idpSso)
  location.searchParams.set('SAMLRequest', encoded)
  if (relayState) location.searchParams.set('RelayState', relayState)
  return new Response(null, {
    status: 302,
    headers: { Location: location.toString(), 'Cache-Control': 'no-store' },
  })
}

// --------------------------------------------------------------------------
// ACS:接收并验证 Response
// --------------------------------------------------------------------------

function tagText(xml: string, local: string): string | undefined {
  return xml
    .match(new RegExp(`<(?:[\\w-]+:)?${local}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w-]+:)?${local}>`))?.[1]
    ?.trim()
}
function attrOf(xml: string, tagLocal: string, attr: string): string | undefined {
  const tag = xml.match(new RegExp(`<(?:[\\w-]+:)?${tagLocal}\\b[^>]*>`))?.[0] ?? ''
  return tag.match(new RegExp(`\\b${attr}\\s*=\\s*"([^"]*)"`))?.[1]
}

export async function spAcs(req: Request, issuer: string): Promise<Response> {
  if (req.method !== 'POST') return page('<p class="bad">ACS 需要 POST。</p>', 405)
  const form = new URLSearchParams(await req.text())
  const samlResponse = form.get('SAMLResponse')
  const relayState = form.get('RelayState')
  if (!samlResponse) return page('<p class="bad">缺少 SAMLResponse。</p>', 400)

  let xml: string
  try {
    xml = new TextDecoder().decode(Uint8Array.from(atob(samlResponse.replace(/\s/g, '')), (c) => c.charCodeAt(0)))
  } catch {
    return page('<p class="bad">SAMLResponse Base64 解码失败。</p>', 400)
  }

  const assertionMatch = xml.match(/<(?:[\w-]+:)?Assertion\b[\s\S]*?<\/(?:[\w-]+:)?Assertion>/)
  const status = attrOf(xml, 'StatusCode', 'Value')
  const responseIssuer = tagText(xml, 'Issuer')
  const nameId = assertionMatch ? tagText(assertionMatch[0], 'NameID') : undefined
  const audience = assertionMatch ? tagText(assertionMatch[0], 'Audience') : undefined
  const inResponseTo = attrOf(xml, 'SubjectConfirmationData', 'InResponseTo')

  // 属性抽取
  const attrs: Array<[string, string]> = []
  if (assertionMatch) {
    const re = /<(?:[\w-]+:)?Attribute\b[^>]*\bName="([^"]*)"[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?Attribute>/g
    let m: RegExpExecArray | null
    while ((m = re.exec(assertionMatch[0]))) {
      const val = tagText(m[0], 'AttributeValue') ?? ''
      attrs.push([m[1], val])
    }
  }

  // 验签(仅本站 IdP 同密钥可自动验证)
  let sigBlock: string
  const isLocalIdp = responseIssuer === idpEntityId(issuer)
  if (assertionMatch && isLocalIdp) {
    const { signatureValid, digestValid } = await verifyEnveloped(assertionMatch[0])
    sigBlock =
      `<p>${signatureValid ? '<span class="ok">✔ Assertion 签名验证通过</span>' : '<span class="bad">✗ 签名验证失败</span>'}` +
      ` · ${digestValid ? '<span class="ok">✔ 摘要匹配</span>' : '<span class="bad">✗ 摘要不匹配</span>'}` +
      ` <small>(使用本站 Mock IdP 的公钥)</small></p>`
  } else if (assertionMatch) {
    sigBlock =
      '<p class="warn">Response 来自外部 IdP,本 mock 未内置其证书,故未自动验签。' +
      '生产环境的 SP 必须用 IdP Metadata 中的证书验证签名后才能信任断言。</p>'
  } else {
    sigBlock = '<p class="bad">未找到 Assertion。</p>'
  }

  const attrRows =
    attrs.map(([k, v]) => `<tr><td><code>${esc(k)}</code></td><td>${esc(v)}</td></tr>`).join('') ||
    '<tr><td colspan="2"><em>无</em></td></tr>'
  const success = status === 'urn:oasis:names:tc:SAML:2.0:status:Success'

  return page(`
<h1 class="${success ? 'ok' : 'bad'}">${success ? '✔ SAML 登录成功' : 'SAML 登录未成功'}</h1>
<p>SP <code>${esc(spEntityId(issuer))}</code> 在 ACS 收到并解析了来自 IdP <code>${esc(responseIssuer ?? '?')}</code> 的 Response。</p>
<h2>签名验证</h2>${sigBlock}
<h2>断言摘要</h2>
<table>
<tr><td>StatusCode</td><td><code>${esc(status ?? '?')}</code></td></tr>
<tr><td>NameID</td><td>${esc(nameId ?? '?')}</td></tr>
<tr><td>Audience</td><td><code>${esc(audience ?? '?')}</code>${audience === spEntityId(issuer) ? ' <span class="ok">✔ 与本 SP 匹配</span>' : ' <span class="bad">✗ 不匹配</span>'}</td></tr>
<tr><td>InResponseTo</td><td><code>${esc(inResponseTo ?? '(IdP-initiated,无)')}</code></td></tr>
<tr><td>RelayState</td><td>${esc(relayState ?? '(无)')}</td></tr>
</table>
<h2>属性(AttributeStatement)</h2>
<table><tr><th>Name</th><th>Value</th></tr>${attrRows}</table>
<h2>原始 Response XML</h2>
<pre>${esc(xml)}</pre>
<p><a class="btn" href="/saml/sp/login">重新发起 SP-initiated 登录</a></p>
`)
}

export function spHome(issuer: string): Response {
  return page(`
<h1>🛡️ Mock SAML SP(服务提供方)</h1>
<p>作为一个 SAML SP,与身份提供方(IdP)配对完成 Web Browser SSO。默认对接本站
<a href="${esc(issuer)}/saml/idp/metadata" target="_blank">Mock SAML IdP</a>,可一键端到端体验。</p>
<h2>端点</h2>
<table>
<tr><td>Metadata</td><td><a href="${esc(issuer)}/saml/sp/metadata"><code>${esc(issuer)}/saml/sp/metadata</code></a></td></tr>
<tr><td>ACS(POST)</td><td><code>${esc(issuer)}/saml/sp/acs</code></td></tr>
</table>
<h2>发起登录</h2>
<form method="GET" action="/saml/sp/login">
  <label>IdP SSO URL(默认本站 Mock IdP)</label>
  <input name="idp_sso" value="${esc(issuer)}/saml/idp/sso"/>
  <button class="btn" type="submit">SP-initiated 登录 →</button>
</form>
<p class="warn">流程:本 SP 生成 AuthnRequest(Redirect Binding)→ 跳到 IdP → 选择测试用户 →
IdP 签名 Response 经 POST 回到本 SP 的 ACS → 展示验签与断言解析结果。</p>
`)
}

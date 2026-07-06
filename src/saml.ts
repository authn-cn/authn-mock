/**
 * Mock SAML 2.0 IdP。
 * 端点:
 *   GET  /saml/idp/metadata   —— IdP Metadata(含签名证书、SSO 端点)
 *   GET  /saml/idp/sso        —— HTTP-Redirect Binding 的 AuthnRequest,或本站的用户选择回链
 *   POST /saml/idp/sso        —— HTTP-POST Binding 的 AuthnRequest
 *
 * 仅供测试:签名私钥/证书公开,生成的断言不可用于生产。
 */
import { el, signEnveloped, t, certPem } from './xmldsig'
import { SAML_CERT_B64 } from './keys'
import { USERS } from './users'

const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion'
const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol'
const NF_EMAIL = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
const B_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
const B_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
const AC_PPT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
const NF_BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic'

function idpEntityId(issuer: string): string {
  return `${issuer}/saml/idp/metadata`
}
function ssoUrl(issuer: string): string {
  return `${issuer}/saml/idp/sso`
}
function isoNoMs(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z')
}
function newId(): string {
  return '_' + crypto.randomUUID().replace(/-/g, '')
}

// --------------------------------------------------------------------------
// Metadata
// --------------------------------------------------------------------------

export function idpMetadata(issuer: string): Response {
  const xml =
    '<?xml version="1.0" encoding="UTF-8"?>' +
    el(
      'md:EntityDescriptor',
      { 'xmlns:md': NS_MD, entityID: idpEntityId(issuer) },
      el(
        'md:IDPSSODescriptor',
        { protocolSupportEnumeration: NS_SAMLP, WantAuthnRequestsSigned: 'false' },
        el(
          'md:KeyDescriptor',
          { use: 'signing' },
          el(
            'ds:KeyInfo',
            { 'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#' },
            el('ds:X509Data', {}, el('ds:X509Certificate', {}, SAML_CERT_B64)),
          ),
        ) +
          el('md:NameIDFormat', {}, t(NF_EMAIL)) +
          el('md:SingleSignOnService', { Binding: B_REDIRECT, Location: ssoUrl(issuer) }) +
          el('md:SingleSignOnService', { Binding: B_POST, Location: ssoUrl(issuer) }),
      ),
    )
  return new Response(xml, {
    headers: {
      'Content-Type': 'application/samlmetadata+xml; charset=utf-8',
      'Content-Disposition': 'inline; filename="authn-mock-idp-metadata.xml"',
      'Access-Control-Allow-Origin': '*',
    },
  })
}

// --------------------------------------------------------------------------
// AuthnRequest 解析(仅取需要的字段,正则即可)
// --------------------------------------------------------------------------

interface ParsedAuthnRequest {
  id?: string
  spEntityId?: string
  acsUrl?: string
}

function attr(xml: string, name: string): string | undefined {
  const m = xml.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`))
  return m ? m[1] : undefined
}

function parseAuthnRequest(xml: string): ParsedAuthnRequest {
  const reqTag = xml.match(/<(?:[\w-]+:)?AuthnRequest\b[^>]*>/)?.[0] ?? ''
  const issuer = xml.match(/<(?:[\w-]+:)?Issuer\b[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?Issuer>/)?.[1]?.trim()
  return {
    id: attr(reqTag, 'ID'),
    acsUrl: attr(reqTag, 'AssertionConsumerServiceURL'),
    spEntityId: issuer,
  }
}

async function inflateRaw(bytes: Uint8Array): Promise<string> {
  const ds = new DecompressionStream('deflate-raw')
  const stream = new Blob([bytes]).stream().pipeThrough(ds)
  return new TextDecoder().decode(await new Response(stream).arrayBuffer())
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.replace(/\s/g, ''))
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

// --------------------------------------------------------------------------
// 生成签名 Response
// --------------------------------------------------------------------------

async function buildSignedResponse(opts: {
  issuer: string
  userKey: string
  acsUrl: string
  spEntityId: string
  inResponseTo?: string
}): Promise<string> {
  const { issuer, userKey, acsUrl, spEntityId, inResponseTo } = opts
  const user = USERS[userKey]
  const now = new Date()
  const notOnOrAfter = isoNoMs(new Date(now.getTime() + 5 * 60_000))
  const notBefore = isoNoMs(new Date(now.getTime() - 60_000))
  const instant = isoNoMs(now)
  const assertionId = newId()
  const responseId = newId()
  const sessionIndex = newId()
  const email = String(user.email.email)
  const idp = idpEntityId(issuer)

  // 先构造不含 Signature 的规范化 Assertion
  const subjectConfirmationData = el('saml:SubjectConfirmationData', {
    InResponseTo: inResponseTo,
    NotOnOrAfter: notOnOrAfter,
    Recipient: acsUrl,
  })
  const subject = el(
    'saml:Subject',
    {},
    el('saml:NameID', { Format: NF_EMAIL }, t(email)) +
      el(
        'saml:SubjectConfirmation',
        { Method: 'urn:oasis:names:tc:SAML:2.0:cm:bearer' },
        subjectConfirmationData,
      ),
  )
  const conditions = el(
    'saml:Conditions',
    { NotBefore: notBefore, NotOnOrAfter: notOnOrAfter },
    el('saml:AudienceRestriction', {}, el('saml:Audience', {}, t(spEntityId))),
  )
  const authnStatement = el(
    'saml:AuthnStatement',
    { AuthnInstant: instant, SessionIndex: sessionIndex },
    el('saml:AuthnContext', {}, el('saml:AuthnContextClassRef', {}, t(AC_PPT))),
  )
  const attrs: Record<string, string> = {
    email,
    name: String(user.profile.name),
    given_name: String(user.profile.given_name),
    family_name: String(user.profile.family_name),
  }
  const attributeStatement = el(
    'saml:AttributeStatement',
    {},
    Object.entries(attrs)
      .map(([name, value]) =>
        el(
          'saml:Attribute',
          { Name: name, NameFormat: NF_BASIC },
          el('saml:AttributeValue', {}, t(value)),
        ),
      )
      .join(''),
  )
  const assertion = el(
    'saml:Assertion',
    { 'xmlns:saml': NS_SAML, ID: assertionId, IssueInstant: instant, Version: '2.0' },
    el('saml:Issuer', {}, t(idp)) + subject + conditions + authnStatement + attributeStatement,
  )
  const signedAssertion = await signEnveloped(assertion, assertionId)

  const status = el(
    'samlp:Status',
    {},
    el('samlp:StatusCode', { Value: 'urn:oasis:names:tc:SAML:2.0:status:Success' }),
  )
  const response = el(
    'samlp:Response',
    {
      'xmlns:samlp': NS_SAMLP,
      'xmlns:saml': NS_SAML,
      Destination: acsUrl,
      ID: responseId,
      InResponseTo: inResponseTo,
      IssueInstant: instant,
      Version: '2.0',
    },
    el('saml:Issuer', {}, t(idp)) + status + signedAssertion,
  )
  return '<?xml version="1.0" encoding="UTF-8"?>' + response
}

function autoPostForm(acsUrl: string, samlResponseB64: string, relayState?: string): string {
  const esc = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;')
  const relay = relayState
    ? `<input type="hidden" name="RelayState" value="${esc(relayState)}"/>`
    : ''
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>正在登录…</title></head>
<body onload="document.forms[0].submit()">
<noscript><p>请点击继续以完成登录。</p></noscript>
<form method="POST" action="${esc(acsUrl)}">
<input type="hidden" name="SAMLResponse" value="${esc(samlResponseB64)}"/>
${relay}
<input type="submit" value="继续"/>
</form>
</body></html>`
}

function bytesToB64(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

// --------------------------------------------------------------------------
// SSO 处理
// --------------------------------------------------------------------------

const STYLE_LINK = 'display:block;margin:.6rem 0;padding:.8rem 1.2rem;border:1px solid #3eaf7c;border-radius:8px;text-decoration:none;color:#2c3e50'

function chooseUserPage(params: {
  issuer: string
  acsUrl: string
  spEntityId: string
  inResponseTo?: string
  relayState?: string
}): string {
  const q = new URLSearchParams()
  q.set('acs', params.acsUrl)
  q.set('sp', params.spEntityId)
  if (params.inResponseTo) q.set('rid', params.inResponseTo)
  if (params.relayState) q.set('rs', params.relayState)
  const link = (u: string, label: string) => {
    const qq = new URLSearchParams(q)
    qq.set('user', u)
    return `<a style="${STYLE_LINK}" href="/saml/idp/sso?${qq.toString()}"><strong>${label}</strong></a>`
  }
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>选择测试用户 — Mock SAML IdP</title>
<style>body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;max-width:640px;margin:3rem auto;padding:0 1.2rem;color:#2c3e50;line-height:1.7}</style></head>
<body>
<h1>Mock SAML IdP · 选择测试用户</h1>
<p>SP <code>${params.spEntityId.replace(/</g, '&lt;')}</code> 请求登录,选择一个测试用户以签发断言:</p>
${link('alice', 'Alice Zhang（alice@mock.authn.example）')}
${link('bob', 'Bob Li（bob@mock.authn.example）')}
<p style="background:#fff3cd;border-left:4px solid #e0a800;padding:.7rem 1rem;border-radius:4px">
这是 Mock IdP,没有密码——点谁就是谁。签名证书公开,仅供测试。</p>
</body></html>`
}

export async function samlSso(req: Request, issuer: string): Promise<Response> {
  const url = new URL(req.url)
  let params: URLSearchParams
  if (req.method === 'POST') {
    const ct = req.headers.get('Content-Type') ?? ''
    if (!ct.includes('application/x-www-form-urlencoded')) {
      return new Response('POST 到 SSO 端点需 application/x-www-form-urlencoded', { status: 400 })
    }
    params = new URLSearchParams(await req.text())
  } else {
    params = url.searchParams
  }

  const htmlHeaders = {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
  }

  // 情况 A:已选定用户(本站回链 或 IdP-initiated),直接签发
  const chosenUser = params.get('user')
  if (chosenUser) {
    if (!USERS[chosenUser]) {
      return new Response(`未知测试用户 "${chosenUser}"(可用:${Object.keys(USERS).join(', ')})`, {
        status: 400,
      })
    }
    const acsUrl = params.get('acs')
    const spEntityId = params.get('sp')
    if (!acsUrl || !spEntityId) {
      return new Response('缺少 acs 或 sp 参数(IdP-initiated 需显式提供 SP 的 ACS URL 与 entityID)', {
        status: 400,
      })
    }
    const xml = await buildSignedResponse({
      issuer,
      userKey: chosenUser,
      acsUrl,
      spEntityId,
      inResponseTo: params.get('rid') ?? undefined,
    })
    const form = autoPostForm(acsUrl, bytesToB64(new TextEncoder().encode(xml)), params.get('rs') ?? undefined)
    return new Response(form, { headers: htmlHeaders })
  }

  // 情况 B:收到 AuthnRequest(SP-initiated),解析后渲染用户选择页
  const samlRequest = params.get('SAMLRequest')
  if (!samlRequest) {
    return new Response(
      '缺少 SAMLRequest。SP-initiated 请带 SAMLRequest;IdP-initiated 请带 user、acs、sp 参数。',
      { status: 400, headers: htmlHeaders },
    )
  }
  let xml: string
  try {
    const bytes = b64ToBytes(decodeURIComponent(samlRequest))
    if (req.method === 'GET') {
      xml = await inflateRaw(bytes) // Redirect binding:deflate
    } else {
      const asText = new TextDecoder().decode(bytes)
      xml = asText.trimStart().startsWith('<') ? asText : await inflateRaw(bytes)
    }
  } catch {
    return new Response('SAMLRequest 解码失败', { status: 400 })
  }
  const parsed = parseAuthnRequest(xml)
  if (!parsed.acsUrl || !parsed.spEntityId) {
    return new Response('AuthnRequest 缺少 AssertionConsumerServiceURL 或 Issuer', { status: 400 })
  }
  return new Response(
    chooseUserPage({
      issuer,
      acsUrl: parsed.acsUrl,
      spEntityId: parsed.spEntityId,
      inResponseTo: parsed.id,
      relayState: params.get('RelayState') ?? undefined,
    }),
    { headers: htmlHeaders },
  )
}

export { certPem }
